package solution

import (
	"context"
	"net"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

// TestListenPortReadsEitherAddressForm pins the two shapes Codefly hands a
// service for its own endpoint: a rendered cell writes the bare host:port, a
// local run a URL. The bare form is the one url.Parse misreads as a scheme.
func TestListenPortReadsEitherAddressForm(t *testing.T) {
	for address, want := range map[string]string{
		"localhost:8080":         "8080",
		"http://localhost:8080":  "8080",
		"http://127.0.0.1:41234": "41234",
		"[::1]:9000":             "9000",
		"localhost":              "",
		"":                       "",
	} {
		if got := listenPort(address); got != want {
			t.Errorf("listenPort(%q) = %q, want %q", address, got, want)
		}
	}
}

func TestNativeListenerUsesTheAllocatedLoopbackInterface(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "http://127.0.0.1:0"} {
		s := New(Manifest{ID: testSolutionID})
		s.cfg = config{port: listenPort(address), listenHost: listenHost(address), transport: meshTransport{local: true}}
		ln, err := s.listen()
		if err != nil {
			t.Fatal(err)
		}
		bound := ln.Addr().(*net.TCPAddr)
		_ = ln.Close()
		if !bound.IP.IsLoopback() {
			t.Fatalf("native listener exposed on %s", bound)
		}
	}
}

func TestLoadConfigPreservesNativeListenerHostWithAPortOverride(t *testing.T) {
	t.Setenv(resources.ServicePrefix, "backend")
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Setenv(resources.RuntimeContextPrefix, "native")
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__BACKEND__HTTP__HTTP", "http://127.0.0.1:41234")
	t.Setenv("PORT", "41235")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	c := loadConfig(context.Background(), testSolutionID, nil)
	if !c.nativeListener() || c.listenHost != "127.0.0.1" || c.port != "41235" {
		t.Fatalf("native endpoint was not preserved: host=%q port=%q", c.listenHost, c.port)
	}
}

func TestNativeListenerRefusesAnUnresolvedOrNonLoopbackHost(t *testing.T) {
	c := config{port: "8080", gatewayURL: "http://127.0.0.1:8081", brokerInternalToken: "perimeter", profile: "local", transport: meshTransport{local: true}}
	for _, host := range []string{"", "0.0.0.0", "::", "192.0.2.10"} {
		c.listenHost = host
		if err := c.validate(); err == nil {
			t.Fatalf("native host %q admitted", host)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1", "localhost"} {
		c.listenHost = host
		if err := c.validate(); err != nil {
			t.Fatalf("loopback host %q refused: %v", host, err)
		}
	}
}
