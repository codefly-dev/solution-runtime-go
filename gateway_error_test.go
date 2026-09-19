package solution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
					if req.Header().Get("Authorization") != "Bearer viewer-token" {
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
