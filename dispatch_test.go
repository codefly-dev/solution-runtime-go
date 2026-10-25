package solution

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

// The reviewer's reproduction (F1): two operations on one path, a GET a reader
// may make and a POST that writes. The stand-in authority holds only the GET
// row, as a reader's call would. The operation the authority is asked about
// is the operation that runs: a GET runs the GET handler, a POST is refused at
// the authority before the write handler runs, and a method the path does not
// declare is refused by name before the authority is asked or any handler
// runs.
func TestTheOperationCheckedIsTheOperationRun(t *testing.T) {
	ran := []string{}
	handler := func(name string) Handler {
		return func(context.Context, *Gateway) (any, error) {
			ran = append(ran, name)
			return map[string]string{"ran": name}, nil
		}
	}
	items := "/v1/page/items"
	server := New(Manifest{ID: "page", Frontend: []byte(testFrontend)}).Operations(
		Operation{Path: items, Method: "get", Summary: "List the items", Callers: "Readers.", Behavior: "Every item.",
			Response: map[string]string{}, Policy: Requires("page.items", "read"), Handler: handler("read-handler")},
		Operation{Path: items, Method: "post", Summary: "Write an item", Callers: "Writers.", Behavior: "The item written.",
			Response: map[string]string{}, Policy: Requires("page.items", "write"), Handler: handler("write-handler")},
	)
	b := boot(t, server)
	b.authority.mu.Lock()
	b.authority.held = []string{"GET " + items}
	b.authority.mu.Unlock()

	call := func(method string) (int, string) {
		t.Helper()
		request, err := http.NewRequest(method, b.base+items, strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(WorkContextHeader, edgeContext)
		response, err := b.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}

	if code, body := call(http.MethodGet); code != http.StatusOK || !strings.Contains(body, "read-handler") {
		t.Fatalf("GET answered %d %s", code, body)
	}
	if len(ran) != 1 || ran[0] != "read-handler" {
		t.Fatalf("a GET checked as %q ran %v", "GET "+items, ran)
	}
	if checks := b.authority.checks(); len(checks) != 1 || checks[0].GetMethod() != "GET "+items {
		t.Fatalf("the authority was asked %v", checks)
	}

	if code, body := call(http.MethodPost); code != http.StatusForbidden {
		t.Fatalf("a POST the caller does not hold answered %d %s", code, body)
	}
	if len(ran) != 1 {
		t.Fatalf("a refused POST ran %v", ran)
	}
	if checks := b.authority.checks(); len(checks) != 2 || checks[1].GetMethod() != "POST "+items {
		t.Fatalf("the authority was asked %v", checks)
	}

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		code, body := call(method)
		if code != http.StatusMethodNotAllowed {
			t.Errorf("%s, which %s does not declare, answered %d %s", method, items, code, body)
		}
		if method != http.MethodHead && (!strings.Contains(body, method) || !strings.Contains(body, "GET, POST")) {
			t.Errorf("%s was refused without naming why: %s", method, body)
		}
	}
	if len(ran) != 1 || len(b.authority.checks()) != 2 {
		t.Fatalf("an undeclared method reached the authority or a handler: ran %v, checks %v", ran, b.authority.checks())
	}

	// A preflight is the CORS wrapper's, on every declared path.
	if code, _ := call(http.MethodOptions); code != http.StatusNoContent {
		t.Fatalf("a preflight answered %d", code)
	}
}

// served is one documented operation any checked caller may make, for a test
// that is about something other than the operation's documentation.
func served(method, path string, handler Handler) Operation {
	return Operation{Path: path, Method: method, Summary: "Serve " + path, Callers: "Anyone checked.", Behavior: "What the handler returns.",
		Response: map[string]string{}, Policy: AnyCheckedCaller(), Handler: handler}
}

// An operation that cannot be served as declared is refused at boot, by name:
// a route with no policy (the authority would have no row for it), one method
// declared twice on one path (one request, two handlers), or a method that is
// not an operation's.
func TestAnOperationThatCannotBeServedAsDeclaredRefusesTheBoot(t *testing.T) {
	answer := func(context.Context, *Gateway) (any, error) { return nil, nil }
	noPolicy := served("get", "/v1/page/items", answer)
	noPolicy.Policy = nil
	for name, tc := range map[string]struct {
		ops  []Operation
		want string
	}{
		"no policy":      {[]Operation{noPolicy}, "declares no authority policy"},
		"a method twice": {[]Operation{served("get", "/v1/page/items", answer), served("GET", "/v1/page/items", answer)}, "GET /v1/page/items is declared twice"},
		"a preflight":    {[]Operation{served("options", "/v1/page/items", answer)}, `declares the method "options"`},
		"no such method": {[]Operation{served("fetch", "/v1/page/items", answer)}, `declares the method "fetch"`},
	} {
		t.Run(name, func(t *testing.T) {
			err := bootFails(t, New(Manifest{ID: "page", Frontend: []byte(testFrontend)}).Operations(tc.ops...), func() {})
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the boot was refused for %v, want %q", err, tc.want)
			}
		})
	}
}
