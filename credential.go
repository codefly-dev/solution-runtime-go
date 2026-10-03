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
	client, err := workcontext.NewMintClient(s.mintOptions(audience, projectionAudience))
	if err != nil {
		return nil, fmt.Errorf("configure this workload's credential mint at %s: %w", s.cfg.mintURL, err)
	}
	return client, nil
}

// heldToTheFrozenAuthority rechecks the authority whenever a source hands back
// a credential that is not the one it handed back last.
//
// A changed token is a renewal, which is the moment that matters: the host is
// the authority for the principal, the mint audience and the projection
// audience, and a value that drifted after boot must not be re-sealed into a
// new credential. Checking on the *change* rather than on every call keeps this
// a comparison on the hot path.
//
// A drifted authority is terminal, and reported as a refusal rather than as an
// unavailable mint: nothing about it gets better by asking again.
func heldToTheFrozenAuthority(source CredentialSource, authority *codefly.Authority) CredentialSource {
	if authority == nil {
		// No frozen authority to recheck against. Every booted path has one —
		// openAuthority runs before this — so this is the unit-test shape, and
		// wrapping it would only hide the absence.
		return source
	}
	return &authorityHeldSource{inner: source, authority: authority}
}

type authorityHeldSource struct {
	inner     CredentialSource
	authority *codefly.Authority
	mu        sync.Mutex
	last      string
}

func (a *authorityHeldSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	// Before the ask, because the ask is what mints.
	//
	// Rechecking afterwards discovers a withdrawn authority one renewal too
	// late: the mint has already happened, sealed to values nobody approved,
	// and the first caller is served with it. The SDK does this ahead of its
	// own renewals for the platform source; a supplied source has no such
	// hook, which is the whole reason this wrapper exists.
	if err := a.authority.Recheck(ctx); err != nil {
		return workcontext.Credential{}, fmt.Errorf("%w: an authority-bearing value has drifted from the one this process froze at boot, so nothing further is minted under it: %w",
			workcontext.ErrMintRefused, err)
	}
	credential, err := a.inner.Credential(ctx)
	if err != nil {
		return credential, err
	}
	// Before the renewal comparison, because that comparison keys on the
	// token *changing* and a token that is always "" never changes — so the
	// zero credential walked past this wrapper every time.
	if err := usableCredential(credential); err != nil {
		return workcontext.Credential{}, err
	}
	a.mu.Lock()
	renewed := a.last != "" && credential.Token() != a.last
	a.mu.Unlock()
	// And again after, unconditionally — for drift that landed during the ask
	// itself, including the FIRST credential and an ask that returned the one
	// already held. Gating this on the token changing meant a drift arriving
	// mid-ask was not noticed until some later renewal happened to produce a
	// different token.
	_ = renewed
	{
		if err := a.authority.Recheck(ctx); err != nil {
			return workcontext.Credential{}, fmt.Errorf("%w: this execution's credential was renewed while an authority-bearing value had drifted from the one this process froze at boot: %w",
				workcontext.ErrMintRefused, err)
		}
	}
	a.mu.Lock()
	a.last = credential.Token()
	a.mu.Unlock()
	return credential, nil
}

// mintOptions is how this runtime asks the SDK's mint client for a credential.
//
// A function of its own so it can be read in a test. Every field here is a
// decision, and the one most easily lost is Authority: the SDK rechecks it
// before every renewal, which is the single moment a drifted authority value
// would otherwise be laundered into a credential nobody approved. Dropping it
// leaves the boot and the first mint working perfectly and only renewals wrong,
// which is not a shape a test over the happy path can see.
func (s *Server) mintOptions(audience, projectionAudience string) workcontext.MintOptions {
	return workcontext.MintOptions{
		URL:                s.cfg.mintURL,
		Audience:           audience,
		ProjectedToken:     workcontext.ProjectedTokenFile(s.cfg.projectedTokenPath),
		ProjectionAudience: projectionAudience,
		// The frozen reader, not a value read again here: it is what rechecks
		// the three authority-bearing values before each renewal.
		Authority: s.authority,
		// This runtime's own authenticated client, so the mint presents this
		// workload's X.509-SVID, verifies the host against the projected
		// anchor, is unproxied, and does not follow a redirect that would hand
		// the projected token to whatever answered.
		HTTPClient: s.outbound,
	}
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
	// Whatever the source is, the authority recheck is this runtime's promise
	// and not the source's.
	//
	// A supplied source replaces the mint client, and with it every option
	// mintOptions carries — including Authority, which the SDK rechecks before
	// each renewal. So the one guarantee that exists to stop a drifted
	// authority value being laundered into a differently-sealed credential
	// applied to the platform path only, while this package's own
	// documentation promises it of the process. Wrapping here makes the promise
	// true of every source, and it costs the platform source nothing: the SDK
	// does it too, and a recheck of three frozen values is a comparison.
	s.credential = heldToTheFrozenAuthority(s.credential, s.authority)
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
		case err == nil && usableCredential(credential) != nil:
			// A source may hand back the zero credential or an expired one,
			// and this boot used to accept either: it logged a credential
			// sealed to installation "" and served. The classification is
			// usableCredential's — an empty token is a judgement, an expired
			// one is not — so an unavailable answer here keeps waiting inside
			// the window and a refused one fails the boot.
			err = usableCredential(credential)
			if !errors.Is(err, workcontext.ErrMintUnavailable) {
				return fmt.Errorf("obtain this execution's credential from %s: %w", s.cfg.mintURL, err)
			}
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
// credentialAcquirer obtains this execution's credential through the one
// controller that governs every acquisition.
//
// A function rather than the CredentialSource itself, because this path used to
// hold the source and call it directly — so the single-flight, the backoff and
// the held-credential fallback that every other caller goes through did not
// apply to the viewer's mint, which is the hottest path there is. One
// controller means one controller.
type credentialAcquirer func(context.Context) (workcontext.Credential, error)

// attestWorkloadReporting is attestWorkload with somewhere to report a
// *terminal* failure, which is the half that is easy to get backwards.
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
func attestWorkloadReporting(ctx context.Context, acquire credentialAcquirer, report *attestationReport, request *http.Request, id string, terminal func(error)) error {
	if acquire == nil {
		// No source at all is a programming error on a path that mints: every
		// boot opens one, and a consumer that supplied its own supplied a
		// source. Refused rather than treated as "nothing to attest with".
		// (There were two of these branches, identical, one guarded by a
		// condition that made the second unreachable.)
		return fmt.Errorf("%w: this solution holds no credential source, so it cannot attest which module is asking", ErrNotAttested)
	}
	credential, err := acquire(ctx)
	if err != nil {
		report.say(id, "refusing to mint for a viewer: this execution's credential could not be obtained: "+err.Error())
		if terminal != nil && terminalCredentialFailure(err) {
			terminal(err)
		}
		return fmt.Errorf("%w: %w", ErrNotAttested, err)
	}
	// Defence in depth, and unreachable by design since round seven: a
	// credential reaching here has passed usableCredential, which requires a
	// non-empty token and a non-empty seal — and a credential with those came
	// from a mint, so its token parses and Attach succeeds. No test can
	// distinguish this branch any more, which is why no test claims to; it is
	// kept because it does the right thing if the invariant above ever stops
	// holding, unlike the ErrRevoked branch this package deleted for doing the
	// wrong thing while dead.
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
// ErrMintRefused only, and the correction is worth recording because the
// it is easy to get from the wrong direction. It also treated ErrRevoked
// as terminal here, on the reasoning that live state moving under a sound
// credential is as final as a refused build. Two things are wrong with that:
// the mint client does not return ErrRevoked at all (it comes back from a
// *callee* that was shown a capability sealed to state that has moved), and the
// SDK's own contract for it is a refresh and one retry — so treating it as
// terminal would have ended the process on a condition the client is built to
// recover from, if the path had ever been reachable. It was not, which is why
// no test noticed; a dead branch that would do the wrong thing if it ever woke
// up is worse than no branch.
//
// A callee's ErrRevoked is handled where it actually arrives: the far end
// answers 409 with the installation headers, and the capability is dropped from
// the cache so the next call mints (see supersededCapability).
//
// Everything else, ErrMintUnavailable above all, is transient by construction
// and must not end the process: an issuer that cannot reach its own policy log
// is an issuer behaving correctly, and exiting on it would turn a dependency
// blip into a crash loop.
func terminalCredentialFailure(err error) bool {
	return errors.Is(err, workcontext.ErrMintRefused)
}
