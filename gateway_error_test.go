package solution

import (
	"context"
	"errors"
	"fmt"
	"github.com/codefly-dev/sdk-go/workcontext"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestUnaryErrorStatusAcrossHTTPBoundary(t *testing.T) {
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
			var calls atomic.Int32
			upstream := httptest.NewServer(connect.NewUnaryHandler("/example.Service/Read",
				func(_ context.Context, req *connect.Request[emptypb.Empty]) (*connect.Response[emptypb.Empty], error) {
					calls.Add(1)
					if req.Header().Get("Authorization") != viewerBearer() {
						t.Error("viewer credential lost")
					}
					return nil, connect.NewError(tc.code, errors.New("private upstream diagnostic"))
				}))
			defer upstream.Close()
			server := serveHandler(t, upstream.URL, func(ctx context.Context, gw *Gateway) (any, error) {
				_, err := Unary[emptypb.Empty, emptypb.Empty](ctx, gw, "/example.Service/Read", &emptypb.Empty{})
				return nil, fmt.Errorf("private handler context: %w", err)
			})
			resp := viewerRequest(t, server.URL)
			defer drainAndClose(resp)
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.status, body)
			}
			if strings.Contains(string(body), "private") {
				t.Fatalf("diagnostic disclosed: %s", body)
			}
			if calls.Load() != 1 {
				t.Fatalf("dispatches = %d, want exactly one", calls.Load())
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

// TestAHandlerPathCredentialFailureDisclosesNothing is the disclosure a second
// reviewer found behind the "a page sees unavailable" answer, which was only
// ever true of the passthrough.
//
// A Handle or HandleRequest handler returns whatever ForModule gave it. Those
// errors are produced inside this package and deliberately name the mint URL,
// the gateway URL and the issuer's own text, because that is what a boot
// refusal has to say. handlerErrorResponse ended in `err.Error()`, so the
// browser got a 502 carrying all of it — and 502 is the wrong answer anyway:
// the condition is this process's and one renewal fixes it, which is what the
// passthrough path has always reported.
func TestAHandlerPathCredentialFailureDisclosesNothing(t *testing.T) {
	const secretish = "https://mint.internal.example/platform/_credential"
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{"a workload this solution cannot attest for", fmt.Errorf("obtain this execution's credential from %s: 403 forbidden: build 11 is not approved: %w", secretish, ErrNotAttested), http.StatusServiceUnavailable},
		{"a superseded authority", fmt.Errorf("mint at %s: %w", secretish, workcontext.ErrRevoked), http.StatusConflict},
		{"a capability this solution cannot carry", fmt.Errorf("mint at %s: %w", secretish, workcontext.ErrInvalid), http.StatusBadGateway},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, message := handlerErrorResponse(tc.err)
			if status != tc.status {
				t.Errorf("status = %d, want %d: the handler path must answer what the passthrough path answers for the same condition", status, tc.status)
			}
			if strings.Contains(message, secretish) {
				t.Errorf("the message handed to the browser names an internal destination:\n%s", message)
			}
			if strings.Contains(message, "403") || strings.Contains(message, "not approved") {
				t.Errorf("the message handed to the browser carries the issuer's own text:\n%s", message)
			}
			if message == "" {
				t.Error("the message says nothing at all: a page still needs to know whose problem it is")
			}
		})
	}
}

// TestATransportFailureDoesNotNameTheDestination is the disclosure that got
// past the sentinel mapping by a different route.
//
// *url.Error carries the URL it was dialling in Error(), so a mint or gateway
// call that could not connect reached the browser as a 502 naming an internal
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
