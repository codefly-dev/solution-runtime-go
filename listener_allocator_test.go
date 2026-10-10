package solution

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestBoundPortReservesTheExactIPv4LoopbackClientAddress(t *testing.T) {
	ln, port := boundPort(t)
	host, actualPort, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || actualPort != port {
		t.Fatalf("allocated address = %q, want retained IPv4 loopback port %s", ln.Addr(), port)
	}
	competing, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err == nil {
		_ = competing.Close()
		t.Fatal("allocated client address was released before listener handoff")
	}
}

func TestBoundPortHandoffRetainsTheListenerServingTheClient(t *testing.T) {
	ln, port := boundPort(t)
	provideListener(t, ln)
	server := takeListener(&Server{})
	if server.boundListener != ln {
		t.Fatal("boot did not receive the exact allocated listener")
	}
	if takeListener(&Server{}).boundListener != nil {
		t.Fatal("the allocated listener was handed out twice")
	}
	owner := t.Name()
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, owner)
	})}
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(server.boundListener) }()
	t.Cleanup(func() {
		_ = httpServer.Close()
		select {
		case err := <-done:
			if err != http.ErrServerClosed {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("retained listener server did not join")
		}
	})
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	t.Cleanup(client.CloseIdleConnections)
	response, err := client.Get("http://" + net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != owner {
		t.Fatalf("client reached status %d body %q, want the retained listener owner %q", response.StatusCode, body, owner)
	}
}
