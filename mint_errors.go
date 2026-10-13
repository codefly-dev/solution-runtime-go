package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
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
		// Absent is told apart from unusable, and only by asking the
		// filesystem the one question: is there anything at this path. A
		// token that is not there has not been projected yet; one that is
		// there and cannot be used is a projection somebody got wrong.
		_, statErr := os.Lstat(string(path))
		return "", &projectedTokenError{absent: errors.Is(statErr, fs.ErrNotExist)}
	}
	return token, nil
}

type projectedTokenError struct {
	// absent: nothing exists at the projection path.
	absent bool
}

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
	// brokerProjectionAbsent: there is no token at the projection path. The
	// platform has not projected it yet; nothing is sent, and the ask is
	// retried.
	brokerProjectionAbsent
	// brokerAwaitingInstallation: the host admits this workload and has not
	// been asked to install it anywhere yet. The install step arrives on this
	// runtime's own listener; until then there is nothing to mint for.
	brokerAwaitingInstallation
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
	case brokerAwaitingInstallation:
		return "module broker: HTTP 412: no organization has installed this solution yet"
	case brokerOtherStatus:
		return fmt.Sprintf("module broker: HTTP %d: request failed", e.status)
	case brokerInvalidAnswer:
		return "module broker: invalid credential response"
	case brokerProjectionAbsent:
		return "projected service-account token is missing: it has not been projected yet"
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

// retryable reports an answer that judges nothing about this build.
//
// A projection that is not there yet is one of them. The platform projects the
// token, and a process can be running before it has; nothing is sent without
// one, so waiting costs no authority: a boot waits inside its bounded window
// and exits as unavailable if the projection never arrives. A projection that
// is there and unusable — empty, oversized, not a file — is a different thing
// and stays terminal: no amount of waiting repairs it.
func (e *brokerMintError) retryable() bool {
	return e.class == brokerNotEstablished || e.class == brokerAwaitingInstallation || e.class == brokerProjectionAbsent ||
		e.class == brokerTransport &&
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
	case http.StatusPreconditionFailed:
		e.class = brokerAwaitingInstallation
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
