package solution

import (
	"context"
	"errors"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// The pinned execution client predates the broker's redacted error contract.
// Preserve its classifications, but discard its diagnostic and entire cause
// chain before any runtime caller can return or log response or transport text.
type redactedMintSource struct{ client CredentialSource }

func (s *redactedMintSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	credential, err := s.client.Credential(ctx)
	if err == nil {
		return credential, nil
	}
	var projection *projectedTokenError
	if errors.As(err, &projection) {
		return workcontext.Credential{}, &projectedTokenError{}
	}
	switch {
	case errors.Is(err, workcontext.ErrMintRefused):
		return workcontext.Credential{}, workcontext.ErrMintRefused
	case errors.Is(err, workcontext.ErrMintUnavailable):
		return workcontext.Credential{}, workcontext.ErrMintUnavailable
	default:
		return workcontext.Credential{}, errors.New("credential mint failed")
	}
}

// Keep the SDK's bounded, fresh read while making local projection failures
// recognizable without retaining filesystem paths or underlying error text.
type projectedTokenFile string

func (path projectedTokenFile) ProjectedToken() (string, error) {
	token, err := workcontext.ProjectedTokenFile(path).ProjectedToken()
	if err != nil {
		return "", &projectedTokenError{}
	}
	return token, nil
}

type projectedTokenError struct{}

func (*projectedTokenError) Error() string {
	return "projected service-account token is missing, empty, unreadable or exceeds 65536 bytes"
}

func (*projectedTokenError) Unwrap() error { return workcontext.ErrMintUnavailable }
