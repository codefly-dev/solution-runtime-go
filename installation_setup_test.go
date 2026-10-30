package solution

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func setupReceiver(t *testing.T, module *relayedModule, step func(context.Context, Installation) error) (*Server, *interfaceAuthority) {
	t.Helper()
	s, stand := authorityServer(t)
	stand.step = verifiedStep(nil)
	s.cfg.transport = meshTransport{local: true}
	s.OnInstall(step, SetupModule{As: "things", Authority: AuthorityRelay{Group: "page", EndpointKey: "THINGS_ENDPOINT", BindingKey: "THINGS_BINDING"}, Methods: []string{searchName}})
	address := module.serve(t)
	var err error
	s.setupRelays, err = s.openSetupRelays(func(_, key string) (string, error) {
		if key == "THINGS_ENDPOINT" {
			return "grpc://" + address, nil
		}
		return "things-binding", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, r := range s.setupRelays {
			_ = r.conn.Close()
		}
	})
	return s, stand
}

func TestSetupCallbackUsesOnlyIssuedMethodAuthority(t *testing.T) {
	module := &relayedModule{}
	var saved Installation
	s, stand := setupReceiver(t, module, func(ctx context.Context, i Installation) error {
		saved = i
		if _, err := ViewerFromContext(ctx); err == nil {
			return fmt.Errorf("setup received a viewer")
		}
		in, out := thingMessage("GetThingRequest"), thingMessage("Thing")
		setField(in, "entry_id", protoreflect.ValueOfString("setup-item"))
		if err := i.Call(ctx, "things", searchName, in, out); err != nil {
			return err
		}
		if out.Get(out.Descriptor().Fields().ByName("entry_id")).String() != "setup-item" {
			return fmt.Errorf("response lost")
		}
		if err := i.Call(ctx, "things", getName, in, out); err == nil {
			return fmt.Errorf("undeclared method accepted")
		}
		if err := i.Call(ctx, "things", searchName, out, in); err == nil {
			return fmt.Errorf("wrong types accepted")
		}
		return nil
	})
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent {
		t.Fatalf("setup: %d %s", answer.Code, answer.Body)
	}
	asks := stand.asked()
	if len(asks) != 1 || asks[0].GetSetup().GetStepToken() != stepCredential || asks[0].GetSetup().GetMethod() != searchName || asks[0].GetOperationBindingId() != "things-binding" || asks[0].GetActor().GetCredential() != "workload-credential" || len(asks[0].GetScopes()) != 0 {
		t.Fatalf("issue: %v", asks)
	}
	calls := module.observed()
	if len(calls) != 1 || calls[0].method != searchName || calls[0].workContext != "issued-things-binding" || strings.Contains(calls[0].workContext, stepCredential) {
		t.Fatalf("destination: %+v", calls)
	}
	if err := saved.Call(context.Background(), "things", searchName, thingMessage("GetThingRequest"), thingMessage("Thing")); err == nil {
		t.Fatal("retained handle accepted")
	}
	if len(stand.asked()) != 1 {
		t.Fatal("retained handle issued authority")
	}
	mux := http.NewServeMux()
	if err := s.mountPassthrough(mux); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/page"+searchPath, strings.NewReader(`{}`))
	r.Header.Set(WorkContextHeader, edgeContext)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("setup method exposed to viewer: %d", w.Code)
	}
}

func TestSetupCallbackCancellation(t *testing.T) {
	module := &relayedModule{}
	s, stand := setupReceiver(t, module, func(ctx context.Context, i Installation) error {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		return i.Call(canceled, "things", searchName, thingMessage("GetThingRequest"), thingMessage("Thing"))
	})
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusServiceUnavailable {
		t.Fatalf("cancellation: %d", answer.Code)
	}
	if len(stand.asked()) != 0 || len(module.observed()) != 0 {
		t.Fatal("canceled call reached authority or destination")
	}
}

func TestSetupConcurrentAttemptsKeepTheirCredentials(t *testing.T) {
	module := &relayedModule{}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	s, stand := setupReceiver(t, module, func(ctx context.Context, i Installation) error {
		entered <- struct{}{}
		<-release
		return i.Call(ctx, "things", searchName, thingMessage("GetThingRequest"), thingMessage("Thing"))
	})
	stand.step = func(r *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
		copy := proto.Clone(r).(*authorityv1.CheckRequest)
		copy.Token = stepCredential
		result, err := verifiedStep(nil)(copy)
		if err != nil {
			return nil, err
		}
		if r.GetToken() == "step-2" {
			result.Context.Seal.InstallationId = "inst-2"
			result.Context.AuthorityScopes[0].ResourceIds = []string{"inst-2"}
			result.Context.TaskId = "operation-2"
		}
		return result, nil
	}
	second := httptest.NewRequest(http.MethodPost, installationPath, strings.NewReader(`{"installation_id":"inst-2","organization_id":"org-1","revision":3}`))
	second.Header.Set(workcontext.HeaderName, "step-2")
	second.Header.Set(workcontext.InstallationIDHeaderName, "inst-2")
	second.Header.Set(workcontext.InstallationRevisionHeaderName, "3")
	var wg sync.WaitGroup
	answers := make(chan int, 2)
	for _, r := range []*http.Request{stepRequest(stepCredential), second} {
		wg.Add(1)
		go func(r *http.Request) { defer wg.Done(); answers <- install(s, r).Code }(r)
	}
	<-entered
	<-entered
	close(release)
	wg.Wait()
	close(answers)
	for code := range answers {
		if code != http.StatusNoContent {
			t.Fatalf("attempt: %d", code)
		}
	}
	tokens := map[string]bool{}
	for _, ask := range stand.asked() {
		tokens[ask.GetSetup().GetStepToken()] = true
	}
	if len(stand.asked()) != 2 || !tokens[stepCredential] || !tokens["step-2"] {
		t.Fatalf("attempt credentials: %v", tokens)
	}
}

func TestSetupCancellationStopsAnInFlightCall(t *testing.T) {
	module := &relayedModule{unaryStarted: make(chan struct{}), unaryCanceled: make(chan struct{})}
	s, _ := setupReceiver(t, module, func(ctx context.Context, i Installation) error {
		callCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() {
			done <- i.Call(callCtx, "things", searchName, thingMessage("GetThingRequest"), thingMessage("Thing"))
		}()
		select {
		case <-module.unaryStarted:
		case <-time.After(5 * time.Second):
			cancel()
			return fmt.Errorf("module did not receive call")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				return fmt.Errorf("canceled call succeeded")
			}
		case <-time.After(5 * time.Second):
			return fmt.Errorf("call did not cancel")
		}
		select {
		case <-module.unaryCanceled:
			return nil
		case <-time.After(5 * time.Second):
			return fmt.Errorf("destination did not observe cancellation")
		}
	})
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent {
		t.Fatalf("cancellation: %d %s", answer.Code, answer.Body)
	}
}
