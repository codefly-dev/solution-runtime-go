package solution

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"connectrpc.com/connect"
)

// A Connect error a handler returns — a module's answer to a call the handler
// made itself — keeps an actionable status, and its message never reaches the
// browser.
func TestAConnectErrorKeepsItsStatusAcrossTheHTTPBoundary(t *testing.T) {
	for _, tc := range []struct {
		code   connect.Code
		status int
	}{
		{connect.CodeUnauthenticated, 401}, {connect.CodePermissionDenied, 403},
		{connect.CodeNotFound, 404}, {connect.CodeInvalidArgument, 400},
		{connect.CodeOutOfRange, 400}, {connect.CodeAlreadyExists, 409},
		{connect.CodeAborted, 409}, {connect.CodeFailedPrecondition, 412},
		{connect.CodeResourceExhausted, 429}, {connect.CodeDeadlineExceeded, 504},
		{connect.CodeUnavailable, 503}, {connect.CodeInternal, 502},
		{connect.CodeUnknown, 502}, {connect.CodeDataLoss, 502},
		{connect.CodeCanceled, 502}, {connect.CodeUnimplemented, 502},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			err := fmt.Errorf("private handler context: %w", connect.NewError(tc.code, errors.New("private upstream diagnostic")))
			status, message := handlerErrorResponse(err)
			if status != tc.status {
				t.Fatalf("status %d, want %d", status, tc.status)
			}
			if strings.Contains(message, "private") {
				t.Fatalf("diagnostic disclosed: %s", message)
			}
		})
	}
}

func TestGatewayErrorStatusValidation(t *testing.T) {
	for _, status := range []int{0, 103, 200, 302, 400, 401, 403, 404, 409, 422, 429, 500, 501, 502, 503, 504, 999} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			want := http.StatusBadGateway
			if status >= 400 && status <= 499 || status == 503 || status == 504 {
				want = status
			}
			err := fmt.Errorf("private request URL and response body: %w", &GatewayError{StatusCode: status})
			got, message := handlerErrorResponse(err)
			if got != want || message != http.StatusText(want) {
				t.Fatalf("got %d %q, want %d", got, message, want)
			}
		})
	}
}

// TestATransportFailureDoesNotNameTheDestination is the disclosure that got
// past the sentinel mapping by a different route.
//
// *url.Error carries the URL it was dialling in Error(), so a call a handler
// made that could not connect reached the browser as a 502 naming an internal
// address — the same leak the credential sentinels were mapped to stop, arriving
// through the untyped fallthrough and not matched by any of them.
func TestATransportFailureDoesNotNameTheDestination(t *testing.T) {
	const internal = "https://gateway.internal.svc.cluster.local:42152"
	err := &url.Error{Op: "Post", URL: internal + "/platform/_credential", Err: errors.New("dial tcp 10.0.0.5:42152: connect: connection refused")}
	status, message := handlerErrorResponse(fmt.Errorf("mint: %w", err))
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", status)
	}
	if strings.Contains(message, "internal") || strings.Contains(message, "10.0.0.5") {
		t.Errorf("the message handed to the browser names an internal destination:\n%s", message)
	}
	if message == "" {
		t.Error("the message says nothing at all")
	}
}
