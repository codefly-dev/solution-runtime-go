package solution

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"connectrpc.com/connect"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// GatewayError carries a non-success HTTP status received through the host
// gateway. REST adapters should return this rather than flattening the status
// into a string. It exposes no response body, credential or header. Handlers
// may wrap it; only a generic status message reaches the browser.
type GatewayError struct {
	StatusCode int
	// detail is the head of a module's refusal body (Transcoded keeps at most
	// gatewayErrorDetailLimit bytes). Only the consumed-module passthrough reads
	// it, to relay the module's own refusal to the page that made the call; a
	// handler's error never exposes it.
	detail []byte
}

// gatewayErrorDetailLimit bounds the refusal body a GatewayError keeps.
const gatewayErrorDetailLimit = 4 << 10

func (e *GatewayError) Error() string {
	return fmt.Sprintf("gateway returned HTTP %d", e.StatusCode)
}

func handlerErrorResponse(err error) (int, string) {
	var clientErr *ClientError
	if errors.As(err, &clientErr) && clientErr != nil && clientErr.StatusCode >= 400 && clientErr.StatusCode <= 499 {
		return clientErr.StatusCode, clientErr.Message
	}
	var gatewayErr *GatewayError
	if errors.As(err, &gatewayErr) && gatewayErr != nil {
		status := gatewayErr.StatusCode
		if (status >= 400 && status <= 499) || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout {
			return status, http.StatusText(status)
		}
		return http.StatusBadGateway, http.StatusText(http.StatusBadGateway)
	}
	var rpcErr *connect.Error
	if errors.As(err, &rpcErr) && rpcErr != nil {
		status := http.StatusBadGateway
		switch rpcErr.Code() {
		case connect.CodeInvalidArgument, connect.CodeOutOfRange:
			status = http.StatusBadRequest
		case connect.CodeUnauthenticated:
			status = http.StatusUnauthorized
		case connect.CodePermissionDenied:
			status = http.StatusForbidden
		case connect.CodeNotFound:
			status = http.StatusNotFound
		case connect.CodeAlreadyExists, connect.CodeAborted:
			status = http.StatusConflict
		case connect.CodeFailedPrecondition:
			status = http.StatusPreconditionFailed
		case connect.CodeResourceExhausted:
			status = http.StatusTooManyRequests
		case connect.CodeDeadlineExceeded:
			status = http.StatusGatewayTimeout
		case connect.CodeUnavailable:
			status = http.StatusServiceUnavailable
		}
		return status, http.StatusText(status)
	}
	// This runtime's own credential conditions, before the untyped fallthrough
	// below reaches them.
	//
	// These errors are not a handler's to classify and they are not generic:
	// they are produced inside this package, and they carry the mint URL, the
	// gateway URL and the issuer's own message, because that is what a boot
	// refusal needs to name. Left to the fallthrough, a Handle or HandleRequest
	// handler that returned one — which is exactly what a handler does when
	// ForModule fails — answered the browser 502 with that text verbatim.
	//
	// The status was wrong in the same breath as the disclosure. The passthrough
	// path already maps these through relayedError, where ErrNotAttested is
	// unavailable because the condition is this process's and one renewal fixes
	// it; a 502 told the page a module was broken. The two paths now agree, and
	// the message says whose problem it is and nothing about where.
	switch {
	// ErrRevoked first: ErrNotAttested wraps it when a renewal is refused
	// because the state the credential is sealed to has moved, and the first
	// matching branch is what the page is told. It arrives from a *callee* or
	// from a renewal, never from the mint client itself, and it is not terminal
	// — the SDK's contract for it is a refresh and a retry (see
	// terminalCredentialFailure).
	case errors.Is(err, workcontext.ErrRevoked):
		return http.StatusConflict, "the authority this solution presented has been superseded; the call was not made"
	case errors.Is(err, ErrNotAttested):
		return http.StatusServiceUnavailable, "this solution cannot currently act for the viewer against the module"
	case errors.Is(err, workcontext.ErrUnsealed), errors.Is(err, workcontext.ErrNotACoreToken), errors.Is(err, workcontext.ErrInvalid):
		return http.StatusBadGateway, "this solution could not present a usable credential for the module"
	}
	// A transport failure carries the URL it was dialling. *url.Error puts the
	// destination in Error(), so a mint or gateway call that could not connect
	// reached the browser as a 502 naming an internal address — the same
	// disclosure the sentinels above were mapped to stop, arriving by a
	// different route and not caught by matching on them.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return http.StatusBadGateway, "this solution could not reach the platform"
	}
	// Preserve the existing untyped-handler contract. Callers must not put
	// private details in ordinary errors returned to the runtime.
	return http.StatusBadGateway, err.Error()
}
