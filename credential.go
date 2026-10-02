package solution

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// CredentialSource is where this execution's credential comes from.
//
// It is the SDK mint client's own method, so *workcontext.MintClient satisfies
// it directly and this runtime holds no mint of its own: obtaining a credential
// from a projected service-account token, sealing it to a build incarnation and
// an installation, re-reading the rotated projection and rechecking the
// boot-read authority before each renewal are all the SDK's, and this runtime
// decides only when a credential is needed and what happens when there is none.
//
// Every use calls it. The client mints the first credential, hands back the one
// it holds while that one is current, and renews it once it has entered its
// renewal lead — so there is no path through this runtime on which a lapsed
// credential is presented, and no timer here that is not the credential's own
// expiry.
type CredentialSource interface {
	Credential(ctx context.Context) (workcontext.Credential, error)
}

// Credential sets where this execution's credential comes from, replacing the
// platform's mint endpoint. A test, or a consumer whose issuer is reached
// another way, supplies its own. Chainable.
func (s *Server) Credential(source CredentialSource) *Server {
	s.credential = source
	return s
}

// AuthorityGroup is the workspace configuration group through which the
// platform tells this workload the authority-bearing values it runs under: the
// principal it is, the audience it mints against, and the audience its own
// projected token was issued for.
//
// They are read once, at boot, through the SDK's authority reader, and frozen:
// the credential this process holds is sealed to the values it was minted
// under, so a value that resolves differently later is an error and never a
// reload. The reader rechecks them before every renewal, which is the one
// moment a drifted value would otherwise be laundered into a new credential
// sealed to something nobody approved.
const AuthorityGroup = "module-authority"

// The keys of AuthorityGroup. A missing one fails the boot naming
// "module-authority/<KEY>", because the fix is to provision that value and a
// message that did not name it sends whoever reads it looking through all three.
const (
	// AuthorityPrincipalKey is the principal this workload runs as — what the
	// published contract names, and what the delivered authority document
	// grants bindings to.
	AuthorityPrincipalKey = "PRINCIPAL"
	// AuthorityAudienceKey is the Work Context audience this workload mints
	// against, as the host names it.
	AuthorityAudienceKey = "AUDIENCE"
	// AuthorityProjectionAudienceKey is the audience the projected
	// service-account token was itself minted for. It is sent with the mint so
	// the host can refuse a projection aimed at something else, rather than
	// reviewing whatever it is handed.
	AuthorityProjectionAudienceKey = "PROJECTION_AUDIENCE"
)

// readAuthority freezes the authority-bearing values this process runs under.
// The SDK names the missing one in its error, which is the whole reason this
// goes through it rather than three workspace reads: "authority-bearing value
// is not configured: module-authority/AUDIENCE" is actionable where "could not
// mint" is not.
func readAuthority(ctx context.Context) (*codefly.Authority, error) {
	authority, err := codefly.ReadAuthority(ctx,
		codefly.AuthorityValueName{Name: AuthorityGroup, Key: AuthorityPrincipalKey},
		codefly.AuthorityValueName{Name: AuthorityGroup, Key: AuthorityAudienceKey},
		codefly.AuthorityValueName{Name: AuthorityGroup, Key: AuthorityProjectionAudienceKey},
	)
	if err != nil {
		return nil, fmt.Errorf("%w — provision the workspace configuration group %q and declare it as a workspace-configuration dependency of this backend", err, AuthorityGroup)
	}
	return authority, nil
}

// platformCredentialSource is the default source: the SDK's mint client,
// pointed at the host's mint endpoint, presenting the service-account token the
// platform projects for this workload.
//
// It carries this runtime's outbound client, so the mint presents this
// workload's own X.509-SVID, verifies the host against the anchor the platform
// projected, is not proxied, and does not follow redirects: the request carries
// the projected token that attests which workload this process is, and a
// Location would hand that to whatever answered at the mint URL.
func (s *Server) platformCredentialSource() (CredentialSource, error) {
	audience, err := s.authority.Value(AuthorityGroup, AuthorityAudienceKey)
	if err != nil {
		return nil, err
	}
	projectionAudience, err := s.authority.Value(AuthorityGroup, AuthorityProjectionAudienceKey)
	if err != nil {
		return nil, err
	}
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                s.cfg.mintURL,
		Audience:           audience,
		ProjectedToken:     workcontext.ProjectedTokenFile(s.cfg.projectedTokenPath),
		ProjectionAudience: projectionAudience,
		Authority:          s.authority,
		HTTPClient:         s.outbound,
	})
	if err != nil {
		return nil, fmt.Errorf("configure this workload's credential mint at %s: %w", s.cfg.mintURL, err)
	}
	return client, nil
}

// openCredential obtains this execution's credential, once, before the listener
// exists.
//
// The two outcomes the SDK distinguishes are not the same outcome here, and
// conflating them was the first thing the host asked me to change:
//
//   - A **refusal** is the host judging this workload: this build is not the one
//     its presence document approved, the pod's identity does not match, the
//     token attests to another subject. No number of attempts changes any of
//     those answers, so the boot reports what the issuer said and returns —
//     which is a non-zero exit for whoever called Serve, and a redeploy or a
//     corrected delivery for whoever reads it. It is never retried: the old
//     runtime answered every refusal by beating again, minting a fresh
//     single-use token each time, so one undeployable solution produced an
//     audited mint every 15 seconds for as long as it ran.
//
//   - An **unavailable** mint is not a judgement at all. A workload may
//     legitimately start before its presence generation has been applied, and
//     then there is no incarnation to mint against yet; the issuer may also be
//     unable to reach the Kubernetes API or its own policy log, and a host that
//     issues nothing in those cases is a host behaving correctly. Each is
//     transient by construction, so the boot waits and asks again, within a
//     bound.
//
// The bound is what keeps this from being the heartbeat again. It is a boot
// waiting for a dependency, not a process announcing itself: there is no steady
// state in which it runs, nothing is minted on success beyond the one
// credential, and when the bound is spent the boot fails rather than settling
// into a loop. A process that cannot obtain a credential inside it has an
// orchestrator whose job is to restart it, and a restart is cheaper to read
// than a solution that serves nothing while logging forever.
func (s *Server) openCredential(ctx context.Context) error {
	if s.credential == nil {
		source, err := s.platformCredentialSource()
		if err != nil {
			return err
		}
		s.credential = source
	}
	window := s.firstMintWindow
	if window == 0 {
		window = firstMintWait
	}
	// The window is a deadline on the whole operation, not a stopwatch read
	// between attempts. It used to be the latter: elapsed time was checked only
	// after an unavailable answer, so an attempt could start at the deadline
	// and a success after it was accepted — and a source that blocks until its
	// context is cancelled was never cancelled at all, so a boot could wait
	// forever inside one attempt.
	deadline, cancel := context.WithDeadline(ctx, time.Now().Add(window))
	defer cancel()
	// The first wait is a quarter of the window at most, so a window shorter
	// than the backoff still gets more than one attempt. At the real window
	// (two minutes) this is just firstMintRetry; it matters for a caller that
	// sets a short one, where a fixed first backoff would spend the whole
	// window waiting after a single ask.
	wait := firstMintRetry
	if quarter := window / 4; quarter < wait {
		wait = quarter
	}
	for attempt := 1; ; attempt++ {
		credential, err := s.credential.Credential(deadline)
		switch {
		case err == nil && deadline.Err() == nil:
			seal := credential.Seal()
			log.Printf("solution %q: holding one execution credential, sealed to installation %s revision %d and build incarnation %d, valid until %s",
				s.manifest.ID, seal.InstallationID, seal.InstallationRevision, seal.BuildIncarnation,
				credential.ExpiresAt().UTC().Format(time.RFC3339))
			return nil
		case err == nil:
			// A credential that arrived after the window closed is not a
			// credential this boot may act on: the deadline is what bounds the
			// wait, and accepting a late success would make it advisory.
			return fmt.Errorf("obtain this execution's credential from %s: a credential arrived after the %s window closed, so this boot does not hold one",
				s.cfg.mintURL, window)
		case !errors.Is(err, workcontext.ErrMintUnavailable):
			// A judgement, or a configuration this client will not even send.
			return fmt.Errorf("obtain this execution's credential from %s: %w", s.cfg.mintURL, err)
		case deadline.Err() != nil:
			return fmt.Errorf("obtain this execution's credential from %s: still unavailable after %s and %d attempt(s): %w — the issuer answers this way while a presence generation has not been applied yet, or while it cannot reach the Kubernetes API or its policy log; all three are transient, so this is an exit for the orchestrator to retry rather than a judgement on this build",
				s.cfg.mintURL, window, attempt, err)
		}
		if remaining := time.Until(mustDeadline(deadline)); wait > remaining {
			wait = remaining
		}
		log.Printf("solution %q: this execution's credential is not available yet (attempt %d, retrying in %s): %v",
			s.manifest.ID, attempt, wait, err)
		select {
		case <-deadline.Done():
			return fmt.Errorf("obtain this execution's credential from %s: still unavailable after %s and %d attempt(s): %w — the issuer answers this way while a presence generation has not been applied yet, or while it cannot reach the Kubernetes API or its policy log; all three are transient, so this is an exit for the orchestrator to retry rather than a judgement on this build",
				s.cfg.mintURL, window, attempt, err)
		case <-time.After(wait):
		}
		if wait *= 2; wait > firstMintRetryCap {
			wait = firstMintRetryCap
		}
	}
}

// mustDeadline is the deadline of a context that has one. openCredential sets
// it, so the fallback is only there to keep the arithmetic total.
func mustDeadline(ctx context.Context) time.Time {
	if at, ok := ctx.Deadline(); ok {
		return at
	}
	return time.Now()
}

// firstMintWait bounds how long a boot waits for a credential the issuer says
// is not available yet, and firstMintRetry/firstMintRetryCap pace the asks
// inside it.
//
// The bound is deliberately short. What it covers is a workload that started
// before its own presence generation was applied, which is a reconcile away,
// not an outage to ride out — and anything longer is a process holding a pod
// slot while serving nothing, which an orchestrator reads less clearly than an
// exit.
const (
	firstMintWait     = 2 * time.Minute
	firstMintRetry    = 2 * time.Second
	firstMintRetryCap = 15 * time.Second
)

// openAuthority freezes the authority-bearing values this process runs under
// and reports the principal it runs as.
//
// It happens before the contract is resolved and before anything is minted,
// because the principal is part of what the contract publishes and because a
// value the platform never provisioned is a refusal that should not cost a
// round trip to discover.
//
// It happens on **every** path, including a boot that supplied its own
// credential source. A hook changes where a credential comes from; it does not
// change who this workload is. Skipping this for a custom source left the
// published contract naming no principal and the listener held to nothing —
// so the two strongest properties in the boot were off for exactly the
// consumers who had written their own integration.
func (s *Server) openAuthority(ctx context.Context) error {
	authority, err := readAuthority(ctx)
	if err != nil {
		return err
	}
	s.authority = authority
	s.principal, err = authority.Value(AuthorityGroup, AuthorityPrincipalKey)
	return err
}

// attestWorkload presents this execution's credential on a request this runtime
// makes on its own behalf, and refuses the request when it cannot.
//
// It is what makes the credential more than a boot formality: the mint this
// runtime runs for a viewer is an operation performed by *this module*, and
// without the workload's own credential on it the issuer knows only that
// somebody holding a viewer's bearer asked. With it, the issuer can hold the
// mint to the installation and the binding the credential is sealed to — which
// is where that check belongs, since nothing a process reports about itself can
// be trusted by the thing deciding what it may do.
//
// It used to log and carry on. That was fail-open, and it was wrong in the one
// case the attestation exists for: a workload whose renewal the issuer has
// started refusing — because the installation moved, the build is no longer
// approved, the principal's epoch advanced — kept minting viewer capabilities
// with no execution binding on them at all. "The host does not require the
// attestation yet" is a statement about the counterpart's current state, which
// is exactly the kind of concession that leaves a hole open for as long as the
// counterpart takes; and boot-time approval is not authorization at use, which
// is the whole premise of sealing a credential to an execution rather than
// trusting a process that started successfully.
//
// So a credential this runtime cannot present stops the request here. The
// viewer sees a refusal naming this solution's own authority rather than their
// own — the handler maps it to a 503 through relayedError, since the condition
// is this process's and one renewal fixes it — and no capability is minted
// under an attribution nobody can check.
func attestWorkload(ctx context.Context, source CredentialSource, report *attestationReport, request *http.Request, id string) error {
	return attestWorkloadReporting(ctx, source, report, request, id, nil)
}

// attestWorkloadReporting is attestWorkload with somewhere to report a
// *terminal* failure, which is the half the first round got wrong.
//
// The boot already separates the issuer's two answers and must: a refusal is a
// judgement on this build — the installation moved, the build is not the one
// the presence document approved, the principal's epoch advanced — and no
// number of attempts changes it, while an unavailable mint is a transient
// condition worth waiting out. At *renewal* both were collapsed into
// ErrNotAttested, which relayedError maps to unavailable with the note that one
// renewal fixes it. For a refusal that is false: nothing fixes it, so the
// process answered 503 to every request, forever, while reporting itself
// healthy — the one shape this cutover was supposed to end, because a solution
// that serves nothing while looking alive is exactly what the delivered-presence
// model replaced the heartbeat to avoid.
//
// A terminal refusal therefore ends the process. Health starts failing so the
// host's own probe takes the binding out, and serve returns non-zero so the
// orchestrator restarts it against the delivery as it now stands — which is
// where a build the host no longer approves gets resolved, and it is not here.
func attestWorkloadReporting(ctx context.Context, source CredentialSource, report *attestationReport, request *http.Request, id string, terminal func(error)) error {
	if source == nil && terminal == nil {
		return fmt.Errorf("%w: this solution holds no credential source, so it cannot attest which module is asking", ErrNotAttested)
	}
	if source == nil {
		// No source at all is a programming error on a path that mints: every
		// boot opens one, and a consumer that supplied its own supplied a
		// source. Refused rather than treated as "nothing to attest with".
		return fmt.Errorf("%w: this solution holds no credential source, so it cannot attest which module is asking", ErrNotAttested)
	}
	credential, err := source.Credential(ctx)
	if err != nil {
		report.say(id, "refusing to mint for a viewer: this execution's credential could not be obtained: "+err.Error())
		if terminal != nil && terminalCredentialFailure(err) {
			terminal(err)
		}
		return fmt.Errorf("%w: %w", ErrNotAttested, err)
	}
	if err := credential.Attach(request); err != nil {
		report.say(id, "refusing to mint for a viewer: this execution's credential could not be presented: "+err.Error())
		return fmt.Errorf("%w: %w", ErrNotAttested, err)
	}
	report.recovered(id)
	return nil
}

// ErrNotAttested is what a mint refused for want of this workload's own
// credential reports. It is this solution's condition and not the viewer's, and
// one renewal fixes it, which is what decides the status a handler answers.
var ErrNotAttested = errors.New("this solution could not attest which module is asking")

// attestationReport throttles what attestWorkload says. One per server, not a
// package value, so one solution's failing renewal cannot silence another's in
// a process that runs two.
//
// It still throttles even though a failure now refuses the request: a renewal
// that is failing fails on every request, so a line per call would bury the
// first occurrence under the rest. What a caller gets is not throttled — every
// refused request is refused.
type attestationReport struct {
	mu   sync.Mutex
	last string
}

func (r *attestationReport) say(id, what string) {
	if r == nil {
		log.Printf("solution %q: %s", id, what)
		return
	}
	r.mu.Lock()
	repeat := r.last == what
	r.last = what
	r.mu.Unlock()
	if !repeat {
		log.Printf("solution %q: %s", id, what)
	}
}

// recovered closes an episode, so the next failure is reported even if it is
// the same one. A renewal that recovers and fails again is two occurrences.
func (r *attestationReport) recovered(id string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	had := r.last
	r.last = ""
	r.mu.Unlock()
	if had != "" {
		log.Printf("solution %q: presenting this workload's credential again", id)
	}
}

// terminalCredentialFailure reports whether the issuer's answer is a judgement
// no retry can change.
//
// ErrMintRefused is the host saying this build is not the one its presence
// document approved. ErrRevoked is live state having moved under a credential
// that was sound when it was minted — an installation revision, a principal's
// epoch, a build incarnation. Both are decisions about *this* execution, and
// the only thing that resolves either is a new delivery and a new process.
//
// Everything else, ErrMintUnavailable above all, is transient by construction
// and must not end the process: an issuer that cannot reach its own policy log
// is an issuer behaving correctly, and exiting on it would turn a dependency
// blip into a crash loop.
func terminalCredentialFailure(err error) bool {
	return errors.Is(err, workcontext.ErrMintRefused) || errors.Is(err, workcontext.ErrRevoked)
}
