package solution

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

// testSolutionID and testSolutionTitle are a solution's identity in these
// fixtures. Neutral on purpose: this runtime knows nothing about any specific
// solution, and a product's name in its fixtures is a name the next reader
// copies into production.
const (
	testSolutionID    = "widgets-go"
	testSolutionTitle = "Widgets"
)

// testFrontend is the declared frontend file every booted fixture embeds: the
// file FrontendFileName names, as an author writes it.
const testFrontend = "title: " + testSolutionTitle + "\norder: 1\nexposed_module: ./Page\nhost_contract: 1\n"

// authorityEndpointVariable is how the platform delivers authority/endpoint
// to a process, through the carriers the SDK reads.
const authorityEndpointVariable = "CODEFLY__WORKSPACE_CONFIGURATION__AUTHORITY__ENDPOINT"

// booted is a solution serving on an ephemeral port, with the stand-in
// authority it was composed with.
type booted struct {
	server    *Server
	base      string
	client    *http.Client
	authority *interfaceAuthority
	// stop ends this runtime and waits for serve to return. It is idempotent,
	// and the cleanup calls it too.
	stop func()
}

// bootEnvironment provisions everything a deployed solution's boot reads — the
// projected credential, the authority the composition names, the port, the
// profile — and serves the stand-in authority it names.
//
// Shared by every boot test, including the ones that must fail: a boot refused
// for the reason under test has to be refused with everything else in place,
// or the test is asserting the first missing value instead.
func bootEnvironment(t *testing.T) *interfaceAuthority {
	t.Helper()
	stand, address := interfaceAuthorityAt(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "workload-credential")

	// Bound here and handed to whichever Server this test boots, so the port is
	// never released between being chosen and being served on.
	ln, port := boundPort(t)
	provideListener(t, ln)
	t.Setenv("PORT", port)
	t.Setenv(resources.ServicePrefix, "backend")
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__BACKEND__HTTP__HTTP", ln.Addr().String())
	t.Setenv(authorityEndpointVariable, "grpc://"+address)
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(ContractProfileEnvironmentVariable, localProfile)
	// A test that serves assets provisions the directory before booting, since
	// a boot's configuration is read by the serving goroutine and must not be
	// written after it starts.
	if os.Getenv("ASSETS_DIR") == "" {
		t.Setenv("ASSETS_DIR", t.TempDir())
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	return stand
}

// boot runs the whole boot a deployed solution runs — configuration, the
// authority connection, the relays, the contract, the listener — on an
// ephemeral port.
func boot(t *testing.T, server *Server) *booted {
	t.Helper()
	return bootComponent(t, server, false)
}

func bootComponent(t *testing.T, server *Server, headless bool) *booted {
	t.Helper()
	stand := bootEnvironment(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	takeListener(server)
	if headless {
		server.manifest.Frontend = nil
	}
	ln, err := server.start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.serve(ctx, ln) }()
	var stopped sync.Once
	stop := func() {
		stopped.Do(func() {
			cancel()
			<-served
		})
	}
	t.Cleanup(stop)
	return &booted{
		stop:      stop,
		server:    server,
		base:      "http://127.0.0.1:" + os.Getenv("PORT"),
		client:    &http.Client{Transport: &http.Transport{}},
		authority: stand,
	}
}

// bootFails runs the same boot, after edit has changed its environment, and
// returns what it refused with. The boot is bounded: a boot that neither comes
// up nor fails is a finding, not a harness timeout.
func bootFails(t *testing.T, server *Server, edit func()) error {
	t.Helper()
	bootEnvironment(t)
	if edit != nil {
		edit()
	}
	type outcome struct {
		ln  net.Listener
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		ln, err := takeListener(server).start(context.Background())
		done <- outcome{ln, err}
	}()
	select {
	case got := <-done:
		if got.ln != nil {
			_ = got.ln.Close()
		}
		if got.err == nil {
			t.Fatal("the boot came up; this helper is for boots that must fail")
		}
		return got.err
	case <-time.After(30 * time.Second):
		t.Fatal("the boot neither came up nor failed within 30s")
		return nil
	}
}

// TestBootServesPlainHTTPWithoutAskingTheAuthority: a booted solution answers
// its health and its published documents on a plain-HTTP listener on the
// resolved port, and none of that asks the authority anything.
func TestBootServesPlainHTTPWithoutAskingTheAuthority(t *testing.T) {
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Operations(served("get", "/thing", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil })))

	for range 5 {
		if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
			t.Fatalf("health = %d, want 200 answered on the destination the presence document names", status)
		}
		if status := getStatus(t, solution.client, solution.base+"/.well-known/solution.json"); status != http.StatusOK {
			t.Fatalf("served manifest = %d, want 200", status)
		}
	}
	if checks, issues := len(solution.authority.checks()), len(solution.authority.asked()); checks != 0 || issues != 0 {
		t.Fatalf("boot and health asked the authority %d checks and %d issues, want none", checks, issues)
	}
}

// TestACallWithNoWorkContextIsRefusedNotProxied: a handler call that carries
// no Work Context is a 401 from this runtime, never a 502 from something
// downstream, and the handler does not run.
func TestACallWithNoWorkContextIsRefusedNotProxied(t *testing.T) {
	ran := false
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Operations(served("get", "/thing", func(context.Context, *Gateway) (any, error) { ran = true; return nil, nil })))
	if status := getStatus(t, solution.client, solution.base+"/thing"); status != http.StatusUnauthorized || ran {
		t.Errorf("a call with no Work Context = %d (handler ran: %v), want 401", status, ran)
	}
}

// TestABootWithoutTheAuthorityIsRefused: the authority answers who every
// request is for, so a boot whose composition names none is refused naming
// the slot that fixes it, consumed modules or not.
func TestABootWithoutTheAuthorityIsRefused(t *testing.T) {
	for name, server := range map[string]*Server{
		"a solution that consumes nothing": New(Manifest{ID: testSolutionID}),
		"a solution that consumes modules": New(Manifest{ID: testSolutionID}).Consumes(passthroughModule()),
	} {
		t.Run(name, func(t *testing.T) {
			err := bootFails(t, server, func() { t.Setenv(authorityEndpointVariable, "") })
			if !strings.Contains(err.Error(), AuthorityInterfaceGroup+"/"+AuthorityEndpointKey) {
				t.Fatalf("the refusal does not name %s/%s: %v", AuthorityInterfaceGroup, AuthorityEndpointKey, err)
			}
		})
	}
}

// boundPort binds a listener and returns it with its port, so a test hands the
// *listener* to the boot rather than a port number: binding :0, reading the
// port and closing the socket races everything else in this suite asking the
// OS for an ephemeral port.
func boundPort(t *testing.T) (net.Listener, string) {
	t.Helper()
	// On the loopback address the tests dial, not the wildcard. A wildcard
	// bind succeeds on a port another local process holds on 127.0.0.1, and
	// the test's own client then reaches that process instead.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ln, port
}

// getStatus GETs target through client and returns the status.
func getStatus(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// provideListener parks a bound listener for the Server this test is about to
// boot, and takeListener collects it.
//
// A package-level handoff because the environment is how a boot learns its
// port and the Server does not exist yet when bootEnvironment runs. Safe
// without locking: every test here calls t.Setenv, which forbids t.Parallel,
// so they run one at a time.
var parkedListener net.Listener

func provideListener(t *testing.T, ln net.Listener) {
	t.Helper()
	parkedListener = ln
	t.Cleanup(func() { parkedListener = nil })
}

// takeListener gives the server the listener bootEnvironment bound, if there
// is one. A test that provisioned its environment some other way gets nil and
// the boot binds for itself.
//
// It also embeds the fixture's declared frontend into a server that declared
// none, the way a solution's go:embed does. bootComponent explicitly opts out
// when exercising a headless component.
func takeListener(server *Server) *Server {
	if parkedListener != nil {
		server.boundListener = parkedListener
		parkedListener = nil
	}
	if server.manifest.Frontend == nil {
		server.manifest.Frontend = []byte(testFrontend)
	}
	return server
}

func TestHeadlessComponentBootsWithoutAdvertisingAFrontend(t *testing.T) {
	running := bootComponent(t, New(Manifest{ID: testSolutionID}), true)
	if status := getStatus(t, running.client, running.base+HealthPath); status != http.StatusOK {
		t.Fatalf("headless health: %d", status)
	}
	if status := getStatus(t, running.client, running.base+"/.well-known/solution.json"); status != http.StatusNotFound {
		t.Fatalf("headless component advertised a page: %d", status)
	}
}
