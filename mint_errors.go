package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// Consumer-supplied SDK sources keep their public sentinel contract, but their
// diagnostics and causes are discarded. The native broker preserves its own
// more precise status and transport categories below.
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

// Only safe metadata survives the broker boundary. No body, header, URL,
// parser diagnostic, or underlying transport error is retained.
type brokerErrorClass uint8

const (
	brokerOtherStatus brokerErrorClass = iota
	brokerRefused
	brokerNotEstablished
	brokerTransport
	brokerInvalidAnswer
	brokerProjection
)

type brokerTransportCategory uint8

const (
	brokerTransportOther brokerTransportCategory = iota
	brokerTransportTimeout
	brokerTransportRefused
	brokerTransportReset
	brokerTransportTLS
)

type brokerMintError struct {
	status    int
	class     brokerErrorClass
	transport brokerTransportCategory
}

func (e *brokerMintError) Error() string {
	switch e.class {
	case brokerRefused:
		return fmt.Sprintf("module broker: HTTP %d: request refused", e.status)
	case brokerNotEstablished:
		return "module broker: HTTP 503: execution not established"
	case brokerOtherStatus:
		return fmt.Sprintf("module broker: HTTP %d: request failed", e.status)
	case brokerInvalidAnswer:
		return "module broker: invalid credential response"
	case brokerProjection:
		return "projected service-account token is missing, empty, unreadable or exceeds 65536 bytes"
	}
	switch e.transport {
	case brokerTransportTimeout:
		return "module broker: transport or response read timed out"
	case brokerTransportRefused:
		return "module broker: connection refused"
	case brokerTransportReset:
		return "module broker: connection reset"
	case brokerTransportTLS:
		return "module broker: TLS failure"
	default:
		return "module broker: transport or response read failed"
	}
}
func (e *brokerMintError) retryable() bool {
	return e.class == brokerNotEstablished || e.class == brokerTransport &&
		(e.transport == brokerTransportTimeout || e.transport == brokerTransportRefused || e.transport == brokerTransportReset)
}
func (e *brokerMintError) Unwrap() error {
	if e.class == brokerRefused {
		return workcontext.ErrMintRefused
	}
	if e.retryable() {
		return workcontext.ErrMintUnavailable
	}
	return nil
}
func brokerStatusError(status int) *brokerMintError {
	e := &brokerMintError{status: status, class: brokerOtherStatus}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		e.class = brokerRefused
	case http.StatusServiceUnavailable:
		e.class = brokerNotEstablished
	}
	return e
}
func classifyBrokerTransport(err error) *brokerMintError {
	e := &brokerMintError{class: brokerTransport}
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	var alert tls.AlertError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var roots x509.SystemRootsError
	switch {
	case errors.Is(err, context.Canceled): // cancellation is not an outage
	case errors.Is(err, context.DeadlineExceeded) || brokerTimedOut(err):
		e.transport = brokerTransportTimeout
	case errors.Is(err, syscall.ECONNREFUSED):
		e.transport = brokerTransportRefused
	case errors.Is(err, syscall.ECONNRESET):
		e.transport = brokerTransportReset
	case errors.As(err, &verification), errors.As(err, &record), errors.As(err, &alert), errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &roots):
		e.transport = brokerTransportTLS
	}
	return e
}
func brokerTimedOut(err error) bool {
	if timed, ok := err.(net.Error); ok && timed.Timeout() {
		return true
	}
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		return brokerTimedOut(e.Unwrap())
	case interface{ Unwrap() []error }:
		for _, cause := range e.Unwrap() {
			if brokerTimedOut(cause) {
				return true
			}
		}
	}
	return false
}
