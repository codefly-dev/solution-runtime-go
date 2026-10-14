package solution

import (
	"context"
	"errors"
	"net/http"

	"github.com/codefly-dev/saas-sdk-go/moduleauthority"
)

// These adapters supply the owner's existing seams. No broker wire encoding or
// response parsing belongs to the runtime.
type brokerGateway struct {
	origin string
	client *http.Client
}

func (g brokerGateway) BaseURL() string          { return g.origin }
func (g brokerGateway) HTTPClient() *http.Client { return g.client }

type brokerProjectionToken string

func (t brokerProjectionToken) ProjectedToken() (string, error) { return string(t), nil }

// Map only owner-typed outcomes into the runtime's bounded retry policy. Keep
// no response, transport cause or parser diagnostic that could carry a secret.
func ownerBrokerFailure(ctx context.Context, err error) *brokerMintError {
	if ctx.Err() != nil {
		return classifyBrokerTransport(ctx.Err())
	}
	var response *moduleauthority.BrokerError
	if errors.As(err, &response) {
		return brokerStatusError(response.StatusCode)
	}
	var transport *moduleauthority.BrokerTransportError
	if errors.As(err, &transport) {
		category := brokerTransportOther
		switch transport.Category {
		case moduleauthority.BrokerTransportTimeout:
			category = brokerTransportTimeout
		case moduleauthority.BrokerTransportConnectionRefused:
			category = brokerTransportRefused
		case moduleauthority.BrokerTransportConnectionReset:
			category = brokerTransportReset
		case moduleauthority.BrokerTransportTLS:
			category = brokerTransportTLS
		}
		return &brokerMintError{class: brokerTransport, transport: category}
	}
	return &brokerMintError{class: brokerInvalidAnswer}
}
