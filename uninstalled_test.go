package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
)

// postInstall sends one well-formed install step to a booted runtime as the
// admitted caller, and returns the status it answered.
func postInstall(t *testing.T, b *booted) int {
	t.Helper()
	r := installRequest(t, installBody)
	r.URL.Scheme, r.URL.Host = "https", strings.TrimPrefix(b.base, "https://")
	r.RequestURI = ""
	resp, err := b.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func healthOf(t *testing.T, b *booted) int {
	t.Helper()
	resp, err := b.client.Get(b.base + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestAnUninstalledSolutionServesItsInstallStepAndThenHoldsACredential is the
// order an installation actually happens in, against a host that behaves as
// the real one does: it answers 412 while nothing has installed the solution,
// delivers the install step, and issues only once that step was acknowledged.
//
// A runtime that needs its execution credential to answer the step can never
// be installed by such a host — each waits for the other — and one whose
// health fails while uninstalled is restarted for not being installed.
func TestAnUninstalledSolutionServesItsInstallStepAndThenHoldsACredential(t *testing.T) {
	var active atomic.Bool
	var steps atomic.Int32
	host := newHostMint(t, &hostMint{answer: func() int {
		if active.Load() {
			return 0
		}
		return http.StatusPreconditionFailed
	}})
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
		steps.Add(1)
		return nil
	})
	b := boot(t, s, host)
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second

	if !s.uninstalled() {
		t.Fatal("a boot the host answered 412 does not read as uninstalled")
	}
	if _, held := s.heldCredential(); held {
		t.Fatal("an uninstalled boot holds a credential")
	}
	asked := host.count()

	// Healthy, and answered from what the host already said.
	for range 3 {
		if status := healthOf(t, b); status != http.StatusOK {
			t.Fatalf("health while uninstalled = %d, want 200: a failing probe has the orchestrator restart a solution for not being installed", status)
		}
	}
	if got := host.count(); got != asked {
		t.Fatalf("three probes asked the host %d more time(s); a probe of an uninstalled solution asks nobody", got-asked)
	}

	// The step is delivered while the host still answers 412, exactly as the
	// host orders it, and the host activates only after reading the answer.
	if status := postInstall(t, b); status != http.StatusNoContent {
		t.Fatalf("install step while uninstalled = %d, want 204: the host issues nothing until this step is acknowledged, so refusing it is a solution nobody can install", status)
	}
	if steps.Load() != 1 {
		t.Fatalf("the install step ran %d time(s), want 1", steps.Load())
	}
	time.Sleep(100 * time.Millisecond)
	active.Store(true)

	// Held promptly — well inside the idle cadence, because the acknowledged
	// step is what says the credential is now worth asking for.
	deadline := time.Now().Add(awaitInstallationEvery / 2)
	for {
		if _, held := s.heldCredential(); held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no credential held %s after the install step was acknowledged and the host began issuing", awaitInstallationEvery/2)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.uninstalled() {
		t.Fatal("a runtime holding a credential still reads as uninstalled")
	}
	if status := healthOf(t, b); status != http.StatusOK {
		t.Fatalf("health once installed = %d, want 200", status)
	}
}

// TestARefusalAfterAnUninstalledBootEndsTheProcess: the host admitted this
// workload at boot and judges it differently when next asked. That answer has
// to end the process the way it does on every other path; an ask made around
// the controller logged it and left a process serving on a refused build.
func TestARefusalAfterAnUninstalledBootEndsTheProcess(t *testing.T) {
	var refuse atomic.Bool
	host := newHostMint(t, &hostMint{answer: func() int {
		if refuse.Load() {
			return http.StatusForbidden
		}
		return http.StatusPreconditionFailed
	}})
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error { return nil })
	b := boot(t, s, host)
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second

	refuse.Store(true)
	if status := postInstall(t, b); status != http.StatusNoContent {
		t.Fatalf("install step = %d, want 204", status)
	}
	err, ended := b.ended(10 * time.Second)
	if !ended {
		t.Fatal("the host refused this execution's credential after an uninstalled boot and the process kept serving")
	}
	if err == nil || !strings.Contains(err.Error(), "stopped serving") {
		t.Fatalf("serve returned %v; a refusal is reported as the reason the process ended", err)
	}
}

// TestAnInstalledRuntimeStillHoldsTheInstallStepToItsCredential: the exemption
// is for the one state that needs it. A runtime whose credential the host has
// stopped issuing for any other reason answers the step as it answers a viewer.
func TestAnInstalledRuntimeStillHoldsTheInstallStepToItsCredential(t *testing.T) {
	var steps atomic.Int32
	s, _, _ := brokerFixture(t)
	s.OnInstall(func(context.Context, Installation) error { steps.Add(1); return nil })
	s.noteCredentialAnswer(&brokerMintError{class: brokerTransport})
	s.credentialMu.Lock()
	s.credentialQuietUntil = time.Now().Add(time.Minute)
	s.credentialMu.Unlock()
	if s.uninstalled() {
		t.Fatal("a host that cannot be reached reads as an uninstalled solution")
	}
	w := httptest.NewRecorder()
	s.handleInstallation(w, installRequest(t, installBody))
	if w.Code != http.StatusServiceUnavailable || steps.Load() != 0 {
		t.Fatalf("install step with no obtainable credential = %d after %d run(s), want 503 and none", w.Code, steps.Load())
	}
}

func TestAwaitInstallationCadenceIsJitteredDownward(t *testing.T) {
	low := time.Duration(float64(awaitInstallationEvery) * (1 - awaitInstallationJitter))
	distinct := map[time.Duration]bool{}
	for range 200 {
		wait := awaitInstallationWait()
		if wait > awaitInstallationEvery || wait < low {
			t.Fatalf("wait %s outside [%s, %s]", wait, low, awaitInstallationEvery)
		}
		distinct[wait] = true
	}
	if len(distinct) < 2 {
		t.Fatal("every replica waits the same time, so replicas that boot together ask together")
	}
}

// selfCarrier is the advertised-address carrier for the service these tests
// run as.
func selfCarrier(t *testing.T, value string) []string {
	t.Helper()
	t.Setenv(resources.ModulePrefix, "wiki")
	t.Setenv(resources.ServicePrefix, "backend")
	key := resources.SelfEndpointAsEnvironmentVariableKey(&resources.EndpointInformation{
		Module: "wiki", Service: "backend", Name: "http", API: "http",
	})
	if value == "" {
		return nil
	}
	return []string{key + "=" + value}
}

// TestTheReportedOriginIsTheAdvertisedAddress: a rendered cell hands a service
// its own endpoint as the address it listens on, localized to localhost, and
// the address its peers reach it at under a separate carrier. Reporting the
// former tells the gateway to proxy the solution to the gateway's own loopback.
func TestTheReportedOriginIsTheAdvertisedAddress(t *testing.T) {
	for _, tc := range []struct {
		name, self, port, advertised, want string
	}{
		{"a rendered cell", "localhost:8080", "8080", "http://backend.platform-wiki.svc.cluster.local:8080", "https://backend.platform-wiki.svc.cluster.local:8080"},
		{"a cell whose listen port was overridden", "localhost:8080", "9443", "http://backend.platform-wiki.svc.cluster.local:8080", "https://backend.platform-wiki.svc.cluster.local:8080"},
		{"an advertised host and port with no scheme", "localhost:8080", "8080", "backend.platform-wiki.svc:8080", "https://backend.platform-wiki.svc:8080"},
		{"an advertised IPv6 address", "localhost:8080", "8080", "http://[fd00::12]:8080", "https://[fd00::12]:8080"},
		{"no carrier, on a developer machine", "localhost:22631", "22631", "", "https://localhost:22631"},
		{"no carrier, and a listen port overridden by PORT", "http://127.0.0.1:22631", "9443", "", "https://127.0.0.1:9443"},
		{"no carrier, and a listen address naming no host", ":8080", "8080", "", "https://localhost:8080"},
		{"no carrier, listening on the unspecified address", "0.0.0.0:8080", "8080", "", "https://localhost:8080"},
		{"no carrier and no resolved endpoint", "", "8080", "", "https://localhost:8080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := advertisedOrigin(context.Background(), tc.self, tc.port, selfCarrier(t, tc.advertised))
			if err != nil || got != tc.want {
				t.Fatalf("advertisedOrigin = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// TestAnAdvertisedAddressThatIsNotOneIsRefusedNotReplaced: a carrier that is
// present and wrong is never read as absent. Falling back to the listen
// address is how a typo becomes a loopback upstream.
func TestAnAdvertisedAddressThatIsNotOneIsRefusedNotReplaced(t *testing.T) {
	for name, advertised := range map[string]string{
		"not an address":          "backend",
		"a path":                  "http://backend.platform-wiki.svc.cluster.local:8080/api",
		"userinfo":                "http://ops@backend.platform-wiki.svc.cluster.local:8080",
		"a query":                 "http://backend.platform-wiki.svc.cluster.local:8080?x=1",
		"the unspecified address": "http://0.0.0.0:8080",
		"a port that is not one":  "backend.platform-wiki.svc:0",
	} {
		t.Run(name, func(t *testing.T) {
			got, err := advertisedOrigin(context.Background(), "localhost:8080", "8080", selfCarrier(t, advertised))
			if err == nil || got != "" {
				t.Fatalf("advertisedOrigin(%q) = %q, %v; want a refusal and nothing to report", advertised, got, err)
			}
		})
	}
}

// TestADeployedRuntimeRefusesToReportItsOwnLoopback is the boot refusal: in a
// deployed runtime context a loopback origin is reachable by no peer, whether
// it came from a missing carrier or was advertised.
func TestADeployedRuntimeRefusesToReportItsOwnLoopback(t *testing.T) {
	load := func(t *testing.T, runtimeContext, advertised string) (config, error) {
		t.Helper()
		bootableEnvironment(t)
		t.Setenv(resources.RuntimeContextPrefix, runtimeContext)
		for _, entry := range selfCarrier(t, advertised) {
			key, value, _ := strings.Cut(entry, "=")
			t.Setenv(key, value)
		}
		c := loadConfig(context.Background(), "solution-under-test", nil)
		return c, c.validate()
	}
	t.Run("a developer machine reports its loopback port", func(t *testing.T) {
		c, err := load(t, resources.RuntimeContextNative, "")
		if err != nil || c.upstream != "https://localhost:8090" {
			t.Fatalf("upstream %q, %v; want the loopback port this process listens on", c.upstream, err)
		}
	})
	t.Run("a cell reports the advertised address", func(t *testing.T) {
		c, err := load(t, "kubernetes", "http://backend.platform-wiki.svc.cluster.local:8080")
		if err != nil || c.upstream != "https://backend.platform-wiki.svc.cluster.local:8080" {
			t.Fatalf("upstream %q, %v; want the advertised cluster-local origin", c.upstream, err)
		}
	})
	for name, advertised := range map[string]string{
		"a cell with no carrier":           "",
		"a cell advertising localhost":     "http://localhost:8080",
		"a cell advertising a loopback IP": "http://127.0.0.1:8080",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := load(t, "kubernetes", advertised)
			if err == nil || !strings.Contains(err.Error(), resources.SelfEndpointPrefix) {
				t.Fatalf("validate = %v; want a refusal naming the %s carrier", err, resources.SelfEndpointPrefix)
			}
		})
	}
}

// TestAnOversizeMintRequestIsRefusedAtBoot: the host bounds what it reads and
// answers an oversize body as malformed, which this client can only classify
// as a refusal — at boot and at every renewal after it.
func TestAnOversizeMintRequestIsRefusedAtBoot(t *testing.T) {
	s, _, _ := brokerFixture(t)
	options := s.mintOptions("accounts", func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil })
	options.Authority = fixedAuthority{audience: testAudience}
	options.Manifest = `{"pad":"` + strings.Repeat("a", brokerMintBodyMaxBytes) + `"}`
	if _, err := newBrokerCredentialSource(options); err == nil || !strings.Contains(err.Error(), "manifest") {
		t.Fatalf("an oversize mint request was accepted at boot (%v); it must be refused naming the manifest", err)
	}
	options.Manifest = `{"pad":"` + strings.Repeat("a", brokerMintBodyMaxBytes/2) + `"}`
	if _, err := newBrokerCredentialSource(options); err != nil {
		t.Fatalf("a mint request inside the bound was refused: %v", err)
	}
}
