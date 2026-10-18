package solution

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// credentialController bounds and shares acquisition for one installation.
// Its source and refusal state never cross an organisation boundary.
type credentialController struct {
	nextCredential        credentialAcquirer
	terminalErr           atomic.Pointer[error]
	credentialMu          sync.Mutex
	credentialAsk         *credentialFlight
	credentialAskErr      error
	credentialHeld        executionCredential
	credentialQuietUntil  time.Time
	credentialAskFailures int
}

func (c *credentialController) credentialRefused(err error) {
	c.terminalErr.CompareAndSwap(nil, &err)
}

type credentialScope struct{ organization, installation string }

type scopedCredential struct {
	controller *credentialController
	used       time.Time
	users      int
}

// Bound both retained credentials and outstanding acquisitions. Idle entries
// are evicted only when no acquisition is running; there is no background mint.
const maxCredentialScopes = 256

func (s *Server) acquireForInstallation(ctx context.Context, organization, installation string) (executionCredential, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: request ended", ErrCredentialUnavailable)
	}
	if organization == "" || installation == "" {
		return nil, fmt.Errorf("%w: organisation and installation are required", ErrCredentialRefused)
	}
	key := credentialScope{organization, installation}
	s.scopedMu.Lock()
	entry, found := s.scoped[key]
	if found && entry.controller.terminalErr.Load() != nil {
		// A broker refusal can describe mutable organisation consent, not an
		// execution-wide judgment. Retain its backoff, then re-read authority.
		entry.controller.credentialMu.Lock()
		quiet := time.Now().Before(entry.controller.credentialQuietUntil)
		idle := entry.users == 0 && entry.controller.credentialAsk == nil
		entry.controller.credentialMu.Unlock()
		if !quiet && idle {
			delete(s.scoped, key)
			found = false
		}
	}
	if !found {
		if s.scoped == nil {
			s.scoped = make(map[credentialScope]*scopedCredential)
		}
		if len(s.scoped) >= maxCredentialScopes {
			var oldest credentialScope
			var used time.Time
			for k, candidate := range s.scoped {
				candidate.controller.credentialMu.Lock()
				idle := candidate.users == 0 && candidate.controller.credentialAsk == nil
				candidate.controller.credentialMu.Unlock()
				if idle && (used.IsZero() || candidate.used.Before(used)) {
					oldest, used = k, candidate.used
				}
			}
			if used.IsZero() {
				s.scopedMu.Unlock()
				return nil, ErrCredentialUnavailable
			}
			delete(s.scoped, oldest)
		}
		source, err := s.installationCredentialSource(key)
		if err != nil {
			s.scopedMu.Unlock()
			return nil, err
		}
		entry = &scopedCredential{controller: &credentialController{nextCredential: source}}
	}
	entry.used = time.Now()
	entry.users++
	s.scoped[key] = entry
	s.scopedMu.Unlock()
	defer func() {
		s.scopedMu.Lock()
		entry.users--
		s.scopedMu.Unlock()
	}()
	return entry.controller.credentialWithin(ctx, routeCredentialTimeout)
}

func (s *Server) installationCredentialSource(scope credentialScope) (credentialAcquirer, error) {
	var acquire credentialAcquirer
	if s.credential != nil {
		// The public hook remains usable, but its returned credential must
		// belong to this request. A process-wide source cannot grant another
		// organisation authority by returning its first installation's token.
		source := heldToTheFrozenAuthority(s.credential, s.authority)
		acquire = func(ctx context.Context) (executionCredential, error) { return source.Credential(ctx) }
	} else {
		if s.authority == nil {
			return nil, ErrCredentialRefused
		}
		audience, err := s.authority.Value(AuthorityGroup, AuthorityProjectionAudienceKey)
		if err != nil {
			return nil, err
		}
		options := s.mintOptions(audience)
		options.OrganizationID = scope.organization
		source, err := newBrokerCredentialSource(options)
		if err != nil {
			return nil, err
		}
		acquire = source.Credential
	}
	return func(ctx context.Context) (executionCredential, error) {
		credential, err := acquire(ctx)
		if err != nil {
			return nil, err
		}
		if err := usableCredential(credential); err != nil {
			return nil, err
		}
		// Core alone reads the capability. This is consistency checking of
		// the broker answer, never verification or a replacement for the
		// host's live installation/build checks on each operation.
		if err := matchCredentialScope(credential, scope); err != nil {
			return nil, err
		}
		return credential, nil
	}, nil
}

// credentialWithin bounds one waiter and permits a held unexpired credential
// during transient failure. A recorded refusal always takes precedence.
func (s *credentialController) credentialWithin(ctx context.Context, d time.Duration) (executionCredential, error) {
	// Held and unexpired is the answer whenever the issuer is not answering,
	// and this is the branch that was missing.
	//
	// The timeout path below already served on a held credential, and the
	// error path refused outright — so with the credential inside its renewal
	// window and the issuer answering 503, every viewer request asked, every
	// ask minted, and every request got a 503 while a perfectly valid
	// credential sat in hand. Forty requests, forty audited mints. That is not
	// a smaller version of the heartbeat this runtime deleted, it is a larger
	// one: the heartbeat minted on a timer, this minted on traffic.
	//
	// So a failed ask starts a backoff, and inside it nothing asks again. The
	// renewal the credential's own expiry dictates still happens, because the
	// backoff is shorter than the renewal lead; what cannot happen is one mint
	// per request.
	// The quiet window applies whether or not anything is held, which is the
	// half that was missing: it was consulted only when a credential WAS in
	// hand, so the one state that should ask least — nothing held, the issuer
	// failing — was the state that asked on every single request. The branch
	// meant to back off was the branch that hammered.
	// A recorded judgement first, on every path. The quiet branch below would
	// otherwise re-wrap a terminal refusal as "cannot currently be obtained",
	// which is the one distinction the boot and the run must not disagree on.
	if err := s.terminalErr.Load(); err != nil {
		return workcontext.Credential{}, fmt.Errorf("%w: %w", ErrCredentialRefused, *err)
	}
	if held, quiet, last := s.credentialState(); quiet {
		if held.Token() != "" {
			return held, nil
		}
		if terminalCredentialFailure(last) {
			return workcontext.Credential{}, fmt.Errorf("%w: %w", ErrCredentialRefused, last)
		}
		return workcontext.Credential{}, fmt.Errorf("%w: %w", ErrCredentialUnavailable, last)
	}
	credential, err := s.askOnce(ctx, d)
	if err == nil {
		return credential, nil
	}
	if errors.Is(err, ErrCredentialRefused) {
		return credential, err
	}
	// Unavailable, for any reason including the ask not answering in time. A
	// credential already in hand decides, because renewal begins inside a lead
	// before expiry and refusing here would 503 every viewer over a slow
	// issuer this process does not yet need.
	if held, ok := s.heldCredential(); ok {
		return held, nil
	}
	return credential, err
}

// heldCredential returns only a nonempty, unexpired held credential.
func (s *credentialController) heldCredential() (executionCredential, bool) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()
	if s.credentialHeld == nil || s.credentialHeld.Token() == "" {
		return workcontext.Credential{}, false
	}
	if !time.Now().Before(s.credentialHeld.ExpiresAt()) {
		return workcontext.Credential{}, false
	}
	return s.credentialHeld, true
}

// credentialState reads held authority, backoff and last failure atomically.
func (s *credentialController) credentialState() (held executionCredential, quiet bool, last error) {
	s.credentialMu.Lock()
	defer s.credentialMu.Unlock()
	held = s.credentialHeld
	if held == nil || held.Token() == "" || !time.Now().Before(held.ExpiresAt()) {
		held = workcontext.Credential{}
	}
	last = s.credentialAskErr
	if last == nil {
		last = fmt.Errorf("the credential source has not answered yet")
	}
	return held, time.Now().Before(s.credentialQuietUntil), last
}

// askOnce shares one detached acquisition. Each waiter reads its own immutable
// flight result, never a later flight's result from controller state.
func (s *credentialController) askOnce(ctx context.Context, d time.Duration) (executionCredential, error) {
	s.credentialMu.Lock()
	inflight := s.credentialAsk
	if inflight == nil {
		inflight = &credentialFlight{done: make(chan struct{})}
		s.credentialAsk = inflight
		go s.resolveCredential(ctx, inflight)
	}
	s.credentialMu.Unlock()

	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-inflight.done:
	case <-ctx.Done():
		return workcontext.Credential{}, fmt.Errorf("%w: request ended", ErrCredentialUnavailable)
	case <-timer.C:
		return workcontext.Credential{}, fmt.Errorf("%w: it did not answer within %s", ErrCredentialUnavailable, d)
	}

	// From the flight this caller actually waited on, not from the server's
	// current state. Reading the shared fields let a waiter observe a *later*
	// flight's answer — or none at all, if the next flight had already started
	// and cleared them — so the credential a caller acted on was not
	// necessarily the one its own ask produced. A flight's result is written
	// once, before its channel closes, and never again.
	credential, err := inflight.credential, inflight.err
	if err != nil {
		if terminalCredentialFailure(err) {
			// Keep this scope refused even when no other caller is waiting.
			s.credentialRefused(err)
			return workcontext.Credential{}, fmt.Errorf("%w: %w", ErrCredentialRefused, err)
		}
		return workcontext.Credential{}, fmt.Errorf("%w: %w", ErrCredentialUnavailable, err)
	}
	return credential, nil
}

// resolveCredential records the result even when every waiter has left.
// Caller cancellation cannot cancel other callers' shared acquisition.
func (s *credentialController) resolveCredential(ctx context.Context, flight *credentialFlight) {
	asked, cancel := context.WithTimeout(context.WithoutCancel(ctx), platformRequestTimeout)
	defer cancel()
	credential, err := s.nextCredential(asked)
	if err == nil {
		err = usableCredential(credential)
	}

	// Recorded HERE, where the answer lands, and not only where a caller
	// happens to be waiting for it.
	//
	// This ask runs on a detached context so a request that gives up does not
	// cancel it — which means its answer can arrive after every caller has
	// gone. A terminal refusal classified only by the waiting caller was
	// therefore discarded whenever acquisition outlived its caller: the route
	// served on the held credential, nothing called credentialRefused, and the
	// process went on acting for viewers after its own source had reported
	// this execution refused. The classification belongs to the answer, not to
	// whoever was still listening.
	if err != nil && terminalCredentialFailure(err) {
		s.credentialRefused(err)
	}

	// The flight's own result first, then the shared state. A waiter reads the
	// former and never the latter.
	flight.credential, flight.err = credential, err

	s.credentialMu.Lock()
	s.credentialAskErr = err
	if err != nil {
		s.credentialAskFailures++
		s.credentialQuietUntil = time.Now().Add(credentialAskQuiet(s.credentialAskFailures))
	} else {
		s.credentialHeld = credential
		s.credentialQuietUntil = time.Time{}
		s.credentialAskFailures = 0
	}
	s.credentialAsk = nil
	s.credentialMu.Unlock()
	close(flight.done)
}

func matchCredentialScope(credential executionCredential, scope credentialScope) error {
	decoded, err := corework.Decode(credential.Token())
	if err != nil || decoded.Context().GetOrganizationId() != scope.organization || credential.Seal().GetInstallationId() != scope.installation {
		return workcontext.ErrMintRefused
	}
	return nil
}
