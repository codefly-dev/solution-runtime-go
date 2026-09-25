package solution

import (
	"errors"
	"fmt"
	"net/http"

	"connectrpc.com/connect"
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
	// Preserve the existing untyped-handler contract. Callers must not put
	// private details in ordinary errors returned to the runtime.
	return http.StatusBadGateway, err.Error()
}
