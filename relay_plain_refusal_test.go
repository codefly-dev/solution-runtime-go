package solution

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

// The host gateway refuses a module route in `text/plain`, one short line
// naming the rule that refused. Before this relayed it, the page was told only
// "Forbidden" — the status word — and a viewer who needed a grant on the
// module's installation had nothing to act on. Observed on a cell: every wiki
// page call answered `{"code":"permission_denied","message":"Forbidden"}` while
// the gateway had said "module is not installed for this organization".
func TestGatewayPlainTextRefusalReachesThePage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   connect.Code
	}{
		{"not installed", http.StatusForbidden, "module is not installed for this organization", connect.CodePermissionDenied},
		{"no organization", http.StatusForbidden, "no organization in this session", connect.CodePermissionDenied},
		{"not declared", http.StatusForbidden, "module is not declared on this host", connect.CodePermissionDenied},
		{"trailing newline is trimmed", http.StatusForbidden, "forbidden\n", connect.CodePermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := relayedError(fmt.Errorf("call: %w", &GatewayError{StatusCode: tc.status, detail: []byte(tc.body)}))
			if code := connect.CodeOf(err); code != tc.want {
				t.Fatalf("code = %v, want %v", code, tc.want)
			}
			want := strings.TrimSpace(tc.body)
			if got := connect.CodeOf(err); got == 0 {
				t.Fatalf("unexpected zero code")
			}
			var connectErr *connect.Error
			if !errors.As(err, &connectErr) {
				t.Fatalf("not a connect error: %v", err)
			}
			if connectErr.Message() != want {
				t.Fatalf("message = %q, want %q", connectErr.Message(), want)
			}
			if connectErr.Message() == http.StatusText(tc.status) && want != http.StatusText(tc.status) {
				t.Fatalf("the status word replaced the gateway's reason")
			}
		})
	}
}

// What is NOT plain text stays reported by kind: the relay must not become a
// channel for an accidental body. A multi-line dump, a control character, or a
// body past the bound is exactly what a misconfigured proxy or a panicking
// upstream produces, and none of it is the gateway's own short refusal.
func TestOnlyAShortSingleLineRefusalIsRelayed(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"multi-line stack", "panic: runtime error\n\tgoroutine 1 [running]:\n\tmain.main()"},
		{"control characters", "refused\x00\x07"},
		{"html error page", "<html>\n<head><title>502</title></head>\n</html>"},
		{"past the bound", strings.Repeat("x", relayedMessageLimit+1)},
		{"empty", ""},
		{"whitespace only", "   \n  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := relayedError(fmt.Errorf("call: %w", &GatewayError{StatusCode: http.StatusForbidden, detail: []byte(tc.body)}))
			var connectErr *connect.Error
			if !errors.As(err, &connectErr) {
				t.Fatalf("not a connect error: %v", err)
			}
			if connectErr.Message() != http.StatusText(http.StatusForbidden) {
				t.Fatalf("message = %q, want the status word %q", connectErr.Message(), http.StatusText(http.StatusForbidden))
			}
		})
	}
}

// A 5xx body stays reported by kind: it may be written by an intermediary and
// name an internal address. This is the property TestPassthroughRelaysTheModulesRefusal
// already holds for `upstream connect error: 10.0.0.7:8080 refused`, asserted
// here directly against the relay so the rule is visible where it is written.
func TestA5xxRefusalIsStillReportedByKind(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusInternalServerError} {
		err := relayedError(fmt.Errorf("call: %w", &GatewayError{
			StatusCode: status,
			detail:     []byte("upstream connect error: 10.0.0.7:8080 refused"),
		}))
		var connectErr *connect.Error
		if !errors.As(err, &connectErr) {
			t.Fatalf("not a connect error: %v", err)
		}
		if strings.Contains(connectErr.Message(), "10.0.0.7") {
			t.Fatalf("a 5xx body reached the page: %q", connectErr.Message())
		}
		if connectErr.Message() != http.StatusText(status) {
			t.Fatalf("message = %q, want the status word %q", connectErr.Message(), http.StatusText(status))
		}
	}
}

// A module's own google.rpc.Status body still wins: it carries a code the page
// decodes, and relaying it as text would lose that code.
func TestAJSONStatusBodyStillKeepsItsCode(t *testing.T) {
	err := relayedError(fmt.Errorf("call: %w", &GatewayError{
		StatusCode: http.StatusForbidden,
		detail:     []byte(`{"code":5,"message":"no such collection"}`),
	}))
	if code := connect.CodeOf(err); code != connect.CodeNotFound {
		t.Fatalf("code = %v, want NotFound from the body", code)
	}
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		t.Fatalf("not a connect error: %v", err)
	}
	if connectErr.Message() != "no such collection" {
		t.Fatalf("message = %q", connectErr.Message())
	}
}
