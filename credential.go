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
// It carries this runtime's platform client, so the mint request is not proxied
// and does not follow redirects: it presents the one thing that attests which
// workload this process is, and a Location would hand that to whatever answered
// at the mint URL.
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
		HTTPClient:         platformClient,
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
	wait := firstMintRetry
	window := s.firstMintWindow
	if window == 0 {
		window = firstMintWait
	}
	deadline := time.Now().Add(window)
	for attempt := 1; ; attempt++ {
		credential, err := s.credential.Credential(ctx)
		switch {
		case err == nil:
			seal := credential.Seal()
			log.Printf("solution %q: holding one execution credential, sealed to installation %s revision %d and build incarnation %d, valid until %s",
				s.manifest.ID, seal.InstallationID, seal.InstallationRevision, seal.BuildIncarnation,
				credential.ExpiresAt().UTC().Format(time.RFC3339))
			return nil
		case !errors.Is(err, workcontext.ErrMintUnavailable):
			// A judgement, or a configuration this client will not even send.
			return fmt.Errorf("obtain this execution's credential from %s: %w", s.cfg.mintURL, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("obtain this execution's credential from %s: still unavailable after %s and %d attempt(s): %w — the issuer answers this way while a presence generation has not been applied yet, or while it cannot reach the Kubernetes API or its policy log; all three are transient, so this is an exit for the orchestrator to retry rather than a judgement on this build",
				s.cfg.mintURL, window, attempt, err)
		}
		if wait > remaining {
			wait = remaining
		}
		log.Printf("solution %q: this execution's credential is not available yet (attempt %d, retrying in %s): %v",
			s.manifest.ID, attempt, wait, err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		if wait *= 2; wait > firstMintRetryCap {
			wait = firstMintRetryCap
		}
	}
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
// round trip to discover. A consumer that supplied its own credential source
// has said where its authority comes from, so nothing is read here for it.
func (s *Server) openAuthority(ctx context.Context) error {
	if s.credential != nil {
		return nil
	}
	authority, err := readAuthority(ctx)
	if err != nil {
		return err
	}
	s.authority = authority
	s.principal, err = authority.Value(AuthorityGroup, AuthorityPrincipalKey)
	return err
}

// attestWorkload presents this execution's credential on a request this runtime
// makes on its own behalf.
//
// It is what makes the credential more than a boot formality: the mint this
// runtime runs for a viewer is an operation performed by *this module*, and
// without the workload's own credential on it the issuer knows only that
// somebody holding a viewer's bearer asked. With it, the issuer can hold the
// mint to the installation and the binding the credential is sealed to — which
// is where that check belongs, since nothing a process reports about itself can
// be trusted by the thing deciding what it may do.
//
// A credential that cannot be obtained does not fail the request. The boot
// already established that this build may serve, and the host does not yet
// require this attestation, so failing the viewer's call would break a page
// over a renewal this runtime cannot fix — while the issuer refusing the mint
// is a refusal with the issuer's own reason in it. The cost is real and worth
// stating: between a failed renewal and a recovered one, some mints are
// attributable to this module and some are not, which is a weaker property
// than the boot's (no credential, no listener at all). The alternative is to
// refuse the viewer's call, and it belongs to whoever makes the attestation
// mandatory rather than to this runtime deciding on their behalf.
//
// So it is reported, and throttled: one line per distinct failure rather than
// one per request, because a renewal that is failing fails on every request and
// a log that says so per call buries the first occurrence under the rest.
func attestWorkload(ctx context.Context, source CredentialSource, report *attestationReport, request *http.Request, id string) {
	if source == nil {
		return
	}
	credential, err := source.Credential(ctx)
	if err == nil {
		if attachErr := credential.Attach(request); attachErr != nil {
			report.say(id, "this workload's credential could not be attached to a mint request: "+attachErr.Error())
		} else {
			report.recovered(id)
		}
		return
	}
	report.say(id, "presenting no workload credential on this mint: "+err.Error())
}

// attestationReport throttles what attestWorkload says. One per server, not a
// package value, so one solution's failing renewal cannot silence another's in
// a process that runs two.
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
