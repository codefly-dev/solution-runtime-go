package solution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// Installation describes the installation the host asks this solution to set
// up. Scope is the granted authority, using the same scopes as Consumes.
type Installation struct {
	ID             string
	OrganizationID string
	Revision       uint64
	Scope          []Scope
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
	public := strings.TrimSpace(safe.String())
	if public == "" {
		public = ErrInstallRefused.Error()
	}
	return &installRefusal{reason: public}
}

type installRefusal struct{ reason string }

func (e *installRefusal) Error() string { return e.reason }
func (*installRefusal) Unwrap() error   { return ErrInstallRefused }

// OnInstall registers the install step, before Serve. The host may call again
// after a restart, so the step must converge. Within this Server, every
// completed outcome is retained per installation ID and revision, and a
// concurrent duplicate waits for the first call. ViewerFromContext returns
// the gateway carrying the install call's Work Context for the step's outgoing
// calls; the host verifies that bearer on every call. Chainable.
func (s *Server) OnInstall(step func(context.Context, Installation) error) *Server {
	s.installStep = step
	return s
}

const (
	installationPath     = "/_codefly/installations"
	installationMaxBytes = 64 << 10
	installationFailure  = "installation step failed"
)

// handleInstallation is mounted only by serve, on the workload-identity
// listener. Its allowed-callers file admits the gateway; FromHeaders checks
// the carrier's structure, not its authority. The host verifies the carried
// bearer on each outgoing call, just as it does for viewer calls.
func (s *Server) handleInstallation(w http.ResponseWriter, r *http.Request) {
	token, err := workcontext.FromHeaders(r.Header)
	if err != nil {
		http.Error(w, "invalid work context", http.StatusUnauthorized)
		return
	}
	installation, err := decodeInstallation(w, r)
	if err != nil {
		http.Error(w, "invalid installation", http.StatusBadRequest)
		return
	}
	if err := s.actingForAViewer(r.Context()); err != nil {
		installationOutcome{status: http.StatusServiceUnavailable}.write(w)
		return
	}
	// The supplied capability is the step's bearer. No viewer session is
	// involved, and no viewer capability is minted for an install step.
	gw := s.gatewayFor(nil)
	gw.carriedContext = token
	gw.orgID = installation.OrganizationID
	ctx := context.WithValue(r.Context(), mcpViewerKey{}, gw)
	s.installOnce(ctx, installation).write(w)
}

// decodeInstallation bounds the entire body, including whitespace after the
// object, and accepts exactly one JSON object. Scope's wire spelling is the
// existing accounts spelling; the callback receives the public Scope type.
func decodeInstallation(w http.ResponseWriter, r *http.Request) (Installation, error) {
	var body struct {
		ID             string             `json:"installation_id"`
		OrganizationID string             `json:"organization_id"`
		Revision       uint64             `json:"revision"`
		Scope          []workContextScope `json:"scope"`
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
	if strings.TrimSpace(body.ID) == "" || strings.TrimSpace(body.OrganizationID) == "" || body.Revision == 0 {
		return Installation{}, errors.New("installation_id, organization_id and a positive revision are required")
	}
	return Installation{
		ID: body.ID, OrganizationID: body.OrganizationID,
		Revision: body.Revision, Scope: scopesOfAsk(body.Scope),
	}, nil
}

type installationKey struct {
	id       string
	revision uint64
}

type installationOutcome struct {
	status int
	reason string
}

type installationResult struct {
	done chan struct{}
	installationOutcome
}

// The outcome cache is bounded. Only terminal outcomes are kept — an
// acknowledgement or a refusal — so a transient failure is forgotten once its
// waiters have it, and the host's retry runs the step again. Completed outcomes
// are evicted oldest first past maxInstallOutcomes: the step must converge, so a
// repeat after eviction runs it again rather than answering from memory.
// Steps in flight are never evicted; past maxInstallsInFlight a new one is
// refused as unavailable, which the host retries.
const (
	maxInstallOutcomes  = 1024
	maxInstallsInFlight = 64
)

// installOnce is entered only after caller admission and carrier validation.
// A cached success must never let a repeat bypass that boundary.
func (s *Server) installOnce(ctx context.Context, installation Installation) installationOutcome {
	key := installationKey{id: installation.ID, revision: installation.Revision}
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
	if result.status == http.StatusServiceUnavailable {
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
		return installationOutcome{status: http.StatusNoContent}
	}
	err := s.installStep(ctx, installation)
	if err == nil {
		return installationOutcome{status: http.StatusNoContent}
	}
	if errors.Is(err, ErrInstallRefused) {
		reason := ErrInstallRefused.Error()
		var refusal *installRefusal
		if errors.As(err, &refusal) && refusal != nil {
			reason = refusal.reason
		}
		return installationOutcome{status: http.StatusConflict, reason: reason}
	}
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
