package solution

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// CredentialSource supplies an execution credential from a consumer's issuer.
// The platform broker uses an internal source; this SDK-compatible hook remains
// available to existing consumers without changing their return type.
type CredentialSource interface {
	Credential(ctx context.Context) (workcontext.Credential, error)
}

// Credential sets where this execution's credential comes from, replacing the
// platform's mint endpoint. A test, or a consumer whose issuer is reached
// another way, supplies its own. Source errors retain only ErrMintRefused or
// ErrMintUnavailable classification; their text and causes are discarded.
// Chainable.
func (s *Server) Credential(source CredentialSource) *Server {
	s.credential = source
	if source != nil {
		s.credential = &redactedMintSource{client: source}
	}
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
	// service-account token was itself minted for. The broker requires accounts;
	// this value is checked locally and is not a broker request field.
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
	// mu guards sealed, what this execution's credential was FIRST sealed to.
	// It is frozen for the same reason the authority-bearing values are: every
	// viewer mint this process runs is attested by that credential, and a
	// renewal that quietly moved to another deployment or another build would
	// attribute those mints to an execution that never asked for them.
	mu     sync.Mutex
	sealed sealedIdentity
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
	// And again after, unconditionally — for drift that landed during the ask
	// itself, including the FIRST credential and an ask that returned the one
	// already held. This was once gated on the token having changed, which
	// meant a drift arriving mid-ask went unnoticed until some later renewal
	// happened to produce a different token. Removing the gate left the
	// comparison, the token it remembered and the mutex guarding it all
	// computed and discarded.
	if err := a.authority.Recheck(ctx); err != nil {
		return workcontext.Credential{}, fmt.Errorf("%w: this execution's credential was renewed while an authority-bearing value had drifted from the one this process froze at boot: %w",
			workcontext.ErrMintRefused, err)
	}
	// And the installation the credential is sealed to, frozen at the first one
	// and held there.
	//
	// usableCredential already refuses a credential sealed to no installation.
	// This refuses one sealed to a *different* installation than the credential
	// this process has been acting under — which is not a renewal but a
	// different identity arriving through the renewal path. Every viewer mint
	// names an installation; moving silently would make the mints before and
	// after a renewal name different deployments with nothing recording that
	// they did.
	//
	// Terminal, not transient: the host has answered about a different
	// installation than the one this build was approved for, and no number of
	// retries changes that.
	if err := a.holdSealedIdentity(credential.Seal()); err != nil {
		return workcontext.Credential{}, err
	}
	return credential, nil
}

// holdSealedIdentity freezes what this execution's credential is sealed to —
// the installation AND the execution pair — and refuses a renewal sealed to
// anything else.
//
// usableCredential refuses a credential sealed to no installation and one
// sealed to no execution. This is the other axis: a renewal that is
// well-formed, carries both, and carries DIFFERENT ones. That is not a renewal
// of this execution's credential, it is a different execution's, and the
// executed round found both halves accepted silently — an installation move
// was caught and a build move from incarnation 11 to 99 was not.
//
// It matters for the same reason the installation does. Every work context this
// process mints for a viewer is attested by this credential, so the mints
// before and after a silent change would be attributed to different builds,
// and the host's ceiling for the build it approved would have been applied to
// one it did not. A process whose approved build has moved under it is a
// process that should end and be restarted against the delivery as it now
// stands, which is where that gets resolved.
//
// Read through the SDK's own accessor on the verified seal. No decoder here.
func (a *authorityHeldSource) holdSealedIdentity(seal *workcontext.SealedValues) error {
	held := sealedIdentity{
		installation: seal.GetInstallationId(),
		digest:       seal.GetImageDigest(),
		incarnation:  seal.GetBuildIncarnation(),
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sealed == (sealedIdentity{}) {
		a.sealed = held
		return nil
	}
	if a.sealed == held {
		return nil
	}
	return fmt.Errorf("%w: this execution has been acting under installation %s, image %s, build incarnation %d, and its credential renewed sealed to installation %s, image %s, build incarnation %d. That is a different execution, not a renewal: every work context this process mints for a viewer is attested by this credential, so the mints before and after this point would name a different deployment or a different build — including one the host's approved-build ceiling was never applied to",
		workcontext.ErrMintRefused,
		a.sealed.installation, a.sealed.digest, a.sealed.incarnation,
		held.installation, held.digest, held.incarnation)
}

// sealedIdentity is what a credential is sealed to: which deployment, and
// which build inside it. Compared as one value, because a renewal that changed
// any part of it changed which execution is asking.
type sealedIdentity struct {
	installation string
	digest       string
	incarnation  uint64
}

// mintOptions binds the declared prefix and perimeter credential to the frozen
// authority and the resolved gateway. No environment is read after loadConfig.
func (s *Server) mintOptions(projectionAudience string) brokerMintOptions {
	return brokerMintOptions{
		projectionRead:     &s.projectionRead,
		URL:                s.cfg.mintURL,
		Prefix:             s.manifest.ID,
		InternalToken:      s.cfg.brokerInternalToken,
		Audience:           workcontext.AuthorityValue{Name: AuthorityGroup, Key: AuthorityAudienceKey},
		ProjectedToken:     projectedTokenFile(s.cfg.projectedTokenPath),
		ProjectionAudience: projectionAudience,
		Authority:          s.authority,
		Transport:          s.cfg.transport,
	}
}

// openAuthority freezes the authority-bearing values this process runs under
// and reports the principal it runs as.
//
// It happens before the contract is resolved and before anything is minted,
// because the principal is part of what the contract publishes and because a
// value the platform never provisioned is a refusal that should not cost a
// round trip to discover.
//
// It happens for every authority-consuming declaration, including one with
// a custom credential source. Authority-free declarations skip this step. A hook changes where a credential comes from; it does not
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
type credentialAcquirer func(context.Context) (executionCredential, error)

// attestWorkloadReporting attaches the selected installation credential before
// any viewer mint. Errors retain safe classification and are logged once.
func attestWorkloadReporting(ctx context.Context, acquire credentialAcquirer, report *attestationReport, request *http.Request, id string) error {
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

// terminalCredentialFailure preserves refusals separately from terminal broker
// protocol/configuration errors. Both refuse this acquisition and held fallback.
func terminalCredentialFailure(err error) bool {
	var broker *brokerMintError
	return errors.Is(err, workcontext.ErrMintRefused) ||
		(errors.As(err, &broker) && !broker.retryable())
}
