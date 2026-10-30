package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The install step. The host records an installation pending, and its
// delivery posts the step here, carrying a setup-only credential the
// authority issued for that one pending attempt. The installation becomes
// active only once this answers 204 for it.
//
// Nothing here is decided from the request. The authority verifies the step
// (its Check, at installationStepMethod, which routes to its dedicated step
// verifier and never to ordinary checking): the credential is addressed to
// this module's delivered principal, sealed to the installation and revision,
// bound to the delivered generation, and still the current pending attempt.
// This runtime then requires the body to name exactly what was verified.
//
// The step is given no Gateway. The installation is pending, so nothing it
// holds is active yet, and the setup credential grants delivery of the step
// and explicitly declared setup methods, issued separately by Authority. The
// callback credential is never exposed to solution code or sent to a module.

// Installation is one pending installation of this solution, as the authority
// verified the step for it.
type Installation struct {
	ID             string
	OrganizationID string
	Revision       uint64
	// OperationID is the consent operation the step was issued under (the
	// verified task id). It names the attempt, not the whole consent receipt,
	// whose intent, delivered generation and digest the authority checks. A
	// host retry of the same attempt carries the same operation.
	OperationID string
	setup       *installationSetup
}

// ErrInstallRefused marks an intentional install refusal. Use RefuseInstall
// to attach a public reason; other errors, including wrapping diagnostics,
// never become public response text.
var ErrInstallRefused = errors.New("installation refused")

// RefuseInstall returns an error wrapping ErrInstallRefused with an explicitly
// public reason. The reason is limited to 256 printable ASCII bytes; other
// characters become spaces. Wrapping this error preserves only that reason in
// the response, not the wrapper's diagnostics.
func RefuseInstall(reason string) error {
	return &installRefusal{reason: publicReason(reason, ErrInstallRefused.Error())}
}

type installRefusal struct{ reason string }

func (e *installRefusal) Error() string { return e.reason }
func (*installRefusal) Unwrap() error   { return ErrInstallRefused }

// OnInstall registers the install step, before Serve. The step must converge:
// the host retries after a transient failure, a restart or a lost answer, and
// another replica may run it for the same installation. Within this Server a
// concurrent duplicate waits for the first call, and an acknowledgement is
// answered from memory for the most recent 1024 attempts; a refusal or a
// transient failure is not remembered, so a retry runs the step again.
// ViewerFromContext returns an error inside the step. Chainable.
//
// A solution that declares no step is not installable: the step is refused
// rather than acknowledged, because an acknowledgement is what activates the
// installation, and nothing here set it up.
func (s *Server) OnInstall(step func(context.Context, Installation) error, modules ...SetupModule) *Server {
	s.installStep = step
	s.setupModules = append([]SetupModule(nil), modules...)
	return s
}

const (
	installationPath = "/_codefly/installations"
	// installationStepMethod is what the authority's Check is asked at for an
	// install step: its InstallationStepHTTPMethod, the one method it routes to
	// the step verifier.
	installationStepMethod = "POST " + installationPath
	installationMaxBytes   = 64 << 10
	installationFailure    = "installation step failed"
)

// handleInstallation is mounted only by serve. The order is the boundary:
// carriers and body first, then the authority, then the comparison, and only
// then the ledger, so a remembered acknowledgement is never answered to a
// request the authority did not verify for that very attempt.
func (s *Server) handleInstallation(w http.ResponseWriter, r *http.Request) {
	tokens := r.Header.Values(workcontext.HeaderName)
	if len(tokens) != 1 || tokens[0] == "" {
		http.Error(w, "one installation step credential required", http.StatusUnauthorized)
		return
	}
	installation, err := decodeInstallation(w, r)
	if err != nil {
		log.Printf("solution %q: install step refused: %v", s.manifest.ID, err)
		http.Error(w, "invalid installation", http.StatusBadRequest)
		return
	}
	verified, outcome := s.host.installationStep(r.Context(), tokens[0])
	if verified == nil {
		outcome.write(w)
		return
	}
	if err := sameInstallation(verified, s.host.principal, installation); err != nil {
		// Terminal: the host built this delivery from one record, and a retry
		// of it carries the same disagreement.
		log.Printf("solution %q: install step refused: %v", s.manifest.ID, err)
		installationOutcome{status: http.StatusConflict, reason: "the installation step does not name the installation the authority verified"}.write(w)
		return
	}
	installation.OperationID = verified.GetTaskId()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	installation.setup = &installationSetup{ctx: ctx, server: s, token: tokens[0]}
	s.installOnce(ctx, installation).write(w)
}

// decodeInstallation bounds the entire body, including whitespace after the
// object, and accepts exactly one JSON object with exactly the three fields
// the authority verifies, whose installation the carriers beside the
// credential must name too. Any other member, a scope among them, is refused:
// the step credential verifies nothing else, so nothing else is read.
func decodeInstallation(w http.ResponseWriter, r *http.Request) (Installation, error) {
	var body struct {
		ID             string `json:"installation_id"`
		OrganizationID string `json:"organization_id"`
		Revision       uint64 `json:"revision"`
	}
	reader := http.MaxBytesReader(w, r.Body, installationMaxBytes)
	defer func() { _ = reader.Close() }()
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		return Installation{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Installation{}, errors.New("expected one installation object")
	}
	if body.ID == "" || body.OrganizationID == "" || body.Revision == 0 {
		return Installation{}, errors.New("installation_id, organization_id and a positive revision are required")
	}
	ids, revisions := r.Header.Values(workcontext.InstallationIDHeaderName), r.Header.Values(workcontext.InstallationRevisionHeaderName)
	if len(ids) != 1 || ids[0] != body.ID || len(revisions) != 1 || revisions[0] != strconv.FormatUint(body.Revision, 10) {
		return Installation{}, fmt.Errorf("the %s and %s carriers must each name the body's installation once",
			workcontext.InstallationIDHeaderName, workcontext.InstallationRevisionHeaderName)
	}
	return Installation{ID: body.ID, OrganizationID: body.OrganizationID, Revision: body.Revision}, nil
}

// installationStep asks the authority to verify an install step's credential.
// Never advisory: hop/ENFORCEMENT=warn relaxes a route check, and this is not
// one. A nil context comes with the outcome to answer.
func (h *hostAuthority) installationStep(ctx context.Context, token string) (*authorityv1.WorkContextV1, installationOutcome) {
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	checked, err := h.authority.Check(ctx, &authorityv1.CheckRequest{Token: token, Audience: h.principal, Method: installationStepMethod})
	switch status.Code(err) {
	case codes.OK:
		if checked.GetContext() == nil || checked.GetRefusal() != "" {
			// A refusal beside a context is advice, and this check is never
			// advisory: it is a refusal.
			log.Printf("the authority answered an install step with refusal %q (context present: %t)", checked.GetRefusal(), checked.GetContext() != nil)
			return nil, installationOutcome{status: http.StatusConflict, reason: installationStepRefused}
		}
		return checked.GetContext(), installationOutcome{}
	case codes.PermissionDenied, codes.InvalidArgument, codes.Unauthenticated, codes.NotFound:
		// The authority refuses this credential for this attempt. That ends
		// this delivery, not the installation: a fresh claim or a fresh
		// consent may be issued another. The reason crossing into the host's
		// job history is generic; the authority's own is logged here.
		log.Printf("the authority refuses an install step: %v", status.Convert(err).Message())
		return nil, installationOutcome{status: http.StatusConflict, reason: installationStepRefused}
	}
	// Not now (the attempt changed, or the credential is outside its delivery
	// window), cancelled, or no answer: the installation stays pending and is
	// retried.
	log.Printf("the authority's verification of an install step did not complete: %v", err)
	return nil, installationOutcome{status: http.StatusServiceUnavailable}
}

// installationStepRefused is the one reason an authority refusal of a step
// answers with.
const installationStepRefused = "the authority refuses this installation step"

// sameInstallation requires the verified step to be exactly the one the body
// names, at this module, carrying only the step's own scope. The authority
// checks all of it already; this is the receiver's half the authority's
// verifier asks for, done against what it answered rather than assumed.
func sameInstallation(wc *authorityv1.WorkContextV1, principal string, installation Installation) error {
	scopes := wc.GetAuthorityScopes()
	switch {
	case wc.GetAudience() != principal:
		return fmt.Errorf("the step is addressed to %q, not this module (%q)", wc.GetAudience(), principal)
	case wc.GetOrganizationId() != installation.OrganizationID || wc.GetTenantId() != installation.OrganizationID:
		return fmt.Errorf("the step was verified in organization %q, not %q", wc.GetOrganizationId(), installation.OrganizationID)
	case wc.GetSeal().GetInstallationId() != installation.ID || wc.GetSeal().GetInstallationRevision() != installation.Revision:
		return fmt.Errorf("the step is sealed to installation %q at revision %d, not %q at %d",
			wc.GetSeal().GetInstallationId(), wc.GetSeal().GetInstallationRevision(), installation.ID, installation.Revision)
	case wc.GetTaskId() == "":
		return errors.New("the verified step names no consent operation")
	case len(wc.GetActorChain()) != 0:
		return errors.New("the verified step carries an actor chain")
	case len(scopes) != 1 || scopes[0].GetResourceKind() != "installations" ||
		len(scopes[0].GetActions()) != 1 || scopes[0].GetActions()[0] != "install" ||
		len(scopes[0].GetResourceIds()) != 1 || scopes[0].GetResourceIds()[0] != installation.ID:
		return errors.New("the verified step holds more than installing this installation")
	}
	return nil
}

type installationKey struct {
	id        string
	revision  uint64
	operation string
}

type installationOutcome struct {
	status int
	reason string
}

type installationResult struct {
	done chan struct{}
	installationOutcome
}

// The outcome cache is bounded. Only an acknowledgement is kept: a refusal or a
// transient failure is forgotten once its waiters have it, so the host's retry
// — including an administrator's Retry after fixing the cause, which keeps the
// consent operation — runs the step again. Completed outcomes are evicted oldest first
// past maxInstallOutcomes: the step must converge, so a repeat after eviction
// runs it again rather than answering from memory. Steps in flight are never
// evicted; past maxInstallsInFlight a new one is answered unavailable, which
// the host retries.
const (
	maxInstallOutcomes  = 1024
	maxInstallsInFlight = 64
)

// installOnce is entered only after the authority verified this very attempt.
func (s *Server) installOnce(ctx context.Context, installation Installation) installationOutcome {
	key := installationKey{id: installation.ID, revision: installation.Revision, operation: installation.OperationID}
	s.installMu.Lock()
	if previous := s.installations[key]; previous != nil {
		s.installMu.Unlock()
		select {
		case <-previous.done:
			return previous.installationOutcome
		case <-ctx.Done():
			return installationOutcome{status: http.StatusServiceUnavailable}
		}
	}
	if s.installations == nil {
		s.installations = make(map[installationKey]*installationResult)
	}
	if len(s.installations)-len(s.installCompleted) >= maxInstallsInFlight {
		s.installMu.Unlock()
		return installationOutcome{status: http.StatusServiceUnavailable}
	}
	result := &installationResult{done: make(chan struct{})}
	s.installations[key] = result
	s.installMu.Unlock()

	// The channel publishes the immutable outcome to all waiters. A panicking
	// step is recorded as a failure too, so no duplicate waits forever.
	result.installationOutcome = s.runInstall(ctx, installation)
	s.installMu.Lock()
	if result.status != http.StatusNoContent {
		delete(s.installations, key)
	} else {
		s.installCompleted = append(s.installCompleted, key)
		for len(s.installCompleted) > maxInstallOutcomes {
			delete(s.installations, s.installCompleted[0])
			s.installCompleted = s.installCompleted[1:]
		}
	}
	s.installMu.Unlock()
	close(result.done)
	return result.installationOutcome
}

func (s *Server) runInstall(ctx context.Context, installation Installation) (outcome installationOutcome) {
	outcome.status = http.StatusServiceUnavailable
	defer func() {
		if recover() != nil {
			outcome = installationOutcome{status: http.StatusServiceUnavailable}
		}
	}()
	if s.installStep == nil {
		return installationOutcome{status: http.StatusConflict, reason: "this solution declares no install step"}
	}
	err := s.installStep(ctx, installation)
	if err == nil {
		return installationOutcome{status: http.StatusNoContent}
	}
	var refusal *installRefusal
	if errors.As(err, &refusal) && refusal != nil {
		return installationOutcome{status: http.StatusConflict, reason: refusal.reason}
	}
	if errors.Is(err, ErrInstallRefused) {
		return installationOutcome{status: http.StatusConflict, reason: ErrInstallRefused.Error()}
	}
	log.Printf("solution %q: install step for %s failed: %v", s.manifest.ID, installation.ID, err)
	return outcome
}

func (outcome installationOutcome) write(w http.ResponseWriter) {
	switch outcome.status {
	case http.StatusNoContent:
		w.WriteHeader(http.StatusNoContent)
	case http.StatusConflict:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(struct {
			Reason string `json:"reason"`
		}{Reason: outcome.reason})
	default:
		http.Error(w, installationFailure, http.StatusServiceUnavailable)
	}
}

// publicReason bounds a reason that crosses into the host's job history: 256
// printable ASCII bytes, other characters becoming spaces, and fallback when
// nothing printable is left.
func publicReason(reason, fallback string) string {
	var safe strings.Builder
	for _, r := range reason {
		if safe.Len() == 256 {
			break
		}
		if r < ' ' || r > '~' {
			r = ' '
		}
		safe.WriteByte(byte(r))
	}
	if public := strings.TrimSpace(safe.String()); public != "" {
		return public
	}
	return fallback
}
