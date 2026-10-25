package solution

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"connectrpc.com/connect"
)

// GatewayError carries a non-success HTTP status a handler received from a
// call it made, and the status an authority refusal maps to
// (WorkContextRefusal unwraps to one). REST adapters should return this rather
// than flattening the status into a string. It exposes no response body,
// credential or header. Handlers may wrap it; only a generic status message
// reaches the browser.
type GatewayError struct {
	StatusCode int
}

func (e *GatewayError) Error() string {
	return fmt.Sprintf("HTTP %d", e.StatusCode)
}

func handlerErrorResponse(err error) (int, string) {
	var clientErr *ClientError
	if errors.As(err, &clientErr) && clientErr != nil && clientErr.StatusCode >= 400 && clientErr.StatusCode <= 499 {
		return clientErr.StatusCode, clientErr.Message
	}
	// The authority's refusal of the ask names its reason (WorkContextRefusal).
	var refusal *WorkContextRefusal
	if errors.As(err, &refusal) && refusal != nil && refusal.Reason != "" && refusal.StatusCode >= 400 && refusal.StatusCode <= 499 {
		return refusal.StatusCode, "the authority refused this call: " + refusal.Reason
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
	// A transport failure carries the URL it was dialling. *url.Error puts the
	// destination in Error(), so a call a handler made that could not connect
	// would reach the browser as a 502 naming an internal address.
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return http.StatusBadGateway, "this solution could not reach the platform"
	}
	// Preserve the existing untyped-handler contract. Callers must not put
	// private details in ordinary errors returned to the runtime.
	return http.StatusBadGateway, err.Error()
}

// connectRefusals recognises a Connect or gRPC caller. A Connect unary request
// is told apart from a plain REST POST by its protocol header, which every
// Connect client sends; the kit's REST helpers do not.
var connectRefusals = connect.NewErrorWriter(connect.WithRequireConnectProtocolHeader())

// writeRefusal answers a refused request in the caller's protocol: a Connect
// error — code and message — to a Connect or gRPC client, which reads nothing
// else, and {"error": message} to a plain REST caller. The code is the
// authority's own when the refusal is the authority's, a module's when a
// handler relayed one, and otherwise the one the status maps to.
func writeRefusal(w http.ResponseWriter, r *http.Request, status int, message string, err error) {
	if !connectRefusals.IsSupported(r) {
		writeJSON(w, status, map[string]string{"error": message})
		return
	}
	code := codeForStatus(status)
	var refusal *WorkContextRefusal
	var rpc *connect.Error
	switch {
	case errors.As(err, &refusal) && refusal != nil && refusal.code != 0:
		code = refusal.code
	case errors.As(err, &rpc) && rpc != nil:
		code = rpc.Code()
	}
	_ = connectRefusals.Write(w, r, connect.NewError(code, errors.New(message)))
}
