// Package passthroughtest runs a solution's consumed-module passthrough in a
// test, against a fake host, so a consuming solution can exercise the calls its
// page makes — unary and server-streaming — without a composition.
//
// It serves the real passthrough: Server.PassthroughHandler, the handler Serve
// mounts, checked by the same boot check, over an httptest server. Only the
// host is fake. Host stands in for the gateway the passthrough calls through:
// it mints the viewer's Work Context (the accounts StartTask procedure the
// gateway routes) and forwards each /v1/<as>/* call to the module address the
// test gave it, typically an httptest server of the test's own that answers
// the method's google.api.http binding.
//
//	host := passthroughtest.NewHost(t).Module("widgets", upstream.URL)
//	page := passthroughtest.Start(t, host, declaration...)
//	client := widgetsv1connect.NewWidgetsClient(page.Client(), page.BaseURL("widgets"))
//
// What a green test here does not prove: that a real host admits the
// solution, that accounts grants the scopes, or that the real module answers
// its binding the way the test's stand-in does.
package passthroughtest

import (
	"context"
	"encoding/json"
	"fmt"
	corework "github.com/codefly-dev/core/workcontext"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	"github.com/codefly-dev/sdk-go/workcontext"
	solution "github.com/codefly-dev/solution-runtime-go"
	"github.com/codefly-dev/solution-runtime-go/internal/seam"
)

// startTaskProcedure is the accounts procedure the gateway routes a Work
// Context mint to. It is the host's contract, spoken as Connect JSON.
const startTaskProcedure = "/saas.accounts.v1.WorkContextService/StartTask"

// Viewer is the identity the page calls as: the bearer the browser sends, and
// the organization and session the gateway stamps from it (x-org-id,
// x-session-id) before the call reaches the solution.
type Viewer struct {
	Bearer    string
	OrgID     string
	SessionID string
}

// DefaultViewer is the viewer Solution.Client calls as.
var DefaultViewer = Viewer{
	Bearer:    "Bearer passthroughtest-viewer",
	OrgID:     "passthroughtest-org",
	SessionID: "passthroughtest-session",
}

// Mint is one Work Context the host was asked to mint: the passthrough's
// request, as accounts receives it.
type Mint struct {
	// Token is the capability the host answered with ("" for a refused mint).
	Token     string
	Bearer    string
	OrgID     string
	SessionID string
	// Audience is the module the capability names: its `as`.
	Audience string
	// Scopes is the authority asked for: the method's own, else its module's.
	Scopes []solution.Scope
}

// Call is one call the host forwarded to a module.
type Call struct {
	// Module is the `as` the call was routed under.
	Module string
	// Method and Path are the HTTP verb and path of the module's binding.
	Method string
	Path   string
	// Bearer is the viewer's bearer, as forwarded.
	Bearer string
	// Mint is the mint whose capability the call presented, nil for a call
	// that presented none (a ViewerBearer module) or one this host never
	// minted.
	Mint *Mint
}

// Refusal is the host's refusal of a mint, written the way accounts writes
// one: a Connect error body under an HTTP status.
type Refusal struct {
	// Status is the HTTP status; zero is 403.
	Status int
	// Code is the Connect code ("permission_denied").
	Code    string
	Message string
}

// Host is a fake host gateway: the Work Context mint and the consumed
// modules' prefixes. Its hooks may be set at any time, from any goroutine.
type Host struct {
	server *httptest.Server

	// dir holds the projected files this fake host stands in for.
	dir     string
	mu      sync.Mutex
	modules map[string]*httputil.ReverseProxy
	refuse  func(Mint) *Refusal
	mints   []Mint
	calls   []Call
	// workloadMints counts the solution's own execution credentials.
	workloadMints int
}

// NewHost starts a fake host, closed when the test ends.
func NewHost(t testing.TB) *Host {
	t.Helper()
	h := &Host{modules: map[string]*httputil.ReverseProxy{}, dir: t.TempDir()}
	h.server = httptest.NewServer(http.HandlerFunc(h.serveHTTP))
	t.Cleanup(h.server.Close)
	return h
}

// URL is the host gateway's base URL.
func (h *Host) URL() string { return h.server.URL }

// Module routes the consumed module `as` to upstream, a base URL the host
// forwards every /v1/<as>/* call to, path unchanged — as the gateway forwards
// to a registered module. Every module routed here is also in the solution's
// api.consumes projection. It panics on an upstream that is not an absolute
// URL.
func (h *Host) Module(as, upstream string) *Host {
	target, err := url.Parse(upstream)
	if err != nil || target.Scheme == "" || target.Host == "" {
		panic(fmt.Sprintf("passthroughtest: module %q: upstream %q is not an absolute URL", as, upstream))
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = target.Host
		},
		// A streamed answer is relayed line by line, as it is flushed.
		FlushInterval: -1,
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.modules[as] = proxy
	return h
}

// RefuseMints sets the hook that decides each mint: a non-nil Refusal refuses
// it, the way accounts refuses an authority the viewer does not hold. Nil
// (the default) mints every ask.
func (h *Host) RefuseMints(refuse func(Mint) *Refusal) *Host {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.refuse = refuse
	return h
}

// Mints is every mint the host was asked for, refused ones included, in order.
func (h *Host) Mints() []Mint {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Mint(nil), h.mints...)
}

// Calls is every call the host forwarded to a module, in the order they
// arrived.
func (h *Host) Calls() []Call {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Call(nil), h.calls...)
}

// workloadMintPath is where this fake host mints the solution's own execution
// credential — the same path the runtime derives from its resolved gateway.
//
// It exists because minting for a viewer is fail-closed: a solution that cannot
// attest which module is asking does not ask. A seam that handed the
// passthrough no credential would therefore be a seam in which every call is
// refused, so the fake host mints one, exactly as the real host does.
const workloadMintPath = "/platform/_credential"

// mintWorkload answers the solution's own mint: one credential per execution,
// sealed to this fake host's installation.
func (h *Host) mintWorkload(w http.ResponseWriter, r *http.Request) {
	// The sequence is copied under the lock and the copy is what names the
	// task: reading h.workloadMints again after unlocking is a read of shared
	// state that concurrent mints race on, which the race detector reports with
	// thirty-two of them in flight.
	h.mu.Lock()
	h.workloadMints++
	execution := h.workloadMints
	h.mu.Unlock()
	token, _, err := standInAuthority().Start(r.Context(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             fmt.Sprintf("passthroughtest-execution-%d", execution),
		Audience:           WorkloadAudience,
		OrganizationID:     corework.FixtureOrganization,
		InstallationID:     corework.FixtureInstallation,
		TTL:                10 * time.Minute,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"code": 13, "message": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"work_context": token})
}

// WorkloadAudience is the audience this fake host mints the solution's own
// execution credential for.
const WorkloadAudience = "passthroughtest-workload"

// WorkloadMints is how many execution credentials this host was asked for. A
// correct run asks once, however many calls the page makes.
func (h *Host) WorkloadMints() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.workloadMints
}

// consumes is the api.consumes projection of the routed modules.
func (h *Host) consumes() []manifest.ConsumedAPI {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]manifest.ConsumedAPI, 0, len(h.modules))
	for as := range h.modules {
		out = append(out, manifest.ConsumedAPI{ID: as, Module: as, As: as})
	}
	return out
}

func (h *Host) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == workloadMintPath {
		h.mintWorkload(w, r)
		return
	}
	if r.URL.Path == startTaskProcedure {
		h.mint(w, r)
		return
	}
	as, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	h.mu.Lock()
	proxy := h.modules[as]
	if !strings.HasPrefix(r.URL.Path, "/v1/") || proxy == nil {
		h.mu.Unlock()
		writeJSON(w, http.StatusNotFound, map[string]any{"code": 5, "message": "no module is routed at " + r.URL.Path})
		return
	}
	call := Call{Module: as, Method: r.Method, Path: r.URL.Path, Bearer: r.Header.Get("authorization")}
	if presented := r.Header.Get(workcontext.HeaderName); presented != "" {
		for i := range h.mints {
			if h.mints[i].Token == presented {
				mint := h.mints[i]
				call.Mint = &mint
				break
			}
		}
	}
	h.calls = append(h.calls, call)
	h.mu.Unlock()
	proxy.ServeHTTP(w, r)
}

// mint answers the StartTask procedure as accounts does.
func (h *Host) mint(w http.ResponseWriter, r *http.Request) {
	var ask struct {
		OrgID           string `json:"orgId"`
		SessionID       string `json:"sessionId"`
		Audience        string `json:"audience"`
		AuthorityScopes []struct {
			ResourceKind string   `json:"resourceKind"`
			Actions      []string `json:"actions"`
			ResourceIDs  []string `json:"resourceIds"`
		} `json:"authorityScopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&ask); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"code": "invalid_argument", "message": err.Error()})
		return
	}
	mint := Mint{Bearer: r.Header.Get("authorization"), OrgID: ask.OrgID, SessionID: ask.SessionID, Audience: ask.Audience}
	for _, scope := range ask.AuthorityScopes {
		mint.Scopes = append(mint.Scopes, solution.Scope{ResourceKind: scope.ResourceKind, Actions: scope.Actions, ResourceIDs: scope.ResourceIDs})
	}
	h.mu.Lock()
	refuse := h.refuse
	h.mu.Unlock()
	if refuse != nil {
		if refusal := refuse(mint); refusal != nil {
			h.record(&mint, false)
			status := refusal.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			writeJSON(w, status, map[string]any{"code": refusal.Code, "message": refusal.Message})
			return
		}
	}
	h.record(&mint, true)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":                   mint.Token,
		"orgId":                   mint.OrgID,
		"ownerPrincipalId":        "passthroughtest-viewer",
		"currentActorPrincipalId": "passthroughtest-viewer",
		"expiresAt":               time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
	})
}

// record appends mint, naming its capability after its place in the log when
// it is granted, so a forwarded call is traced to the mint it presents.
func (h *Host) record(mint *Mint, granted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if granted {
		mint.Token = capability(fmt.Sprintf("passthroughtest-%d-%s", len(h.mints)+1, mint.Audience))
	}
	h.mints = append(h.mints, *mint)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Solution is a solution's passthrough served for real against a fake host.
type Solution struct {
	// URL is the solution backend's base URL, where the passthrough serves
	// under solution.PassthroughPathPrefix.
	URL    string
	server *httptest.Server
}

// Handler builds the passthrough for the declaration against host, with the
// modules host routes as the solution's api.consumes: the real handler, and
// the error Serve would refuse the declaration with at boot.
func Handler(host *Host, consumes ...solution.ConsumedModule) (http.Handler, error) {
	source, err := host.credentialSource()
	if err != nil {
		return nil, err
	}
	server := solution.New(solution.Manifest{ID: "passthroughtest"}).
		Consumes(consumes...).
		Credential(source)
	projection, err := json.Marshal(host.consumes())
	if err != nil {
		return nil, err
	}
	// Through internal/seam, because building a credential-bearing handler
	// without the boot is no longer something the runtime's public API can do:
	// exported, that constructor was a production bypass, and this package is
	// the one caller Go's internal-package rule still lets reach it.
	return seam.Passthrough(server, host.URL(), string(projection))
}

// credentialSource is the solution's own execution credential, obtained from
// this fake host through the SDK's mint client — the same client a booted
// runtime uses, so the seam exercises the attestation rather than skipping it.
func (h *Host) credentialSource() (solution.CredentialSource, error) {
	tokenFile := filepath.Join(h.dir, "projected-token")
	if err := os.WriteFile(tokenFile, []byte("passthroughtest-projected-token"), 0o600); err != nil {
		return nil, err
	}
	return workcontext.NewMintClient(workcontext.MintOptions{
		URL:                h.URL() + workloadMintPath,
		Audience:           WorkloadAudience,
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: "accounts",
	})
}

// Start serves the passthrough for the declaration against host, until the
// test ends. A declaration Serve would refuse fails the test.
func Start(t testing.TB, host *Host, consumes ...solution.ConsumedModule) *Solution {
	t.Helper()
	handler, err := Handler(host, consumes...)
	if err != nil {
		t.Fatalf("passthroughtest: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return &Solution{URL: server.URL, server: server}
}

// BaseURL is the base URL a module's generated client takes for the consumed
// module `as`: <URL>/modules/<as>.
func (s *Solution) BaseURL(as string) string {
	return s.URL + solution.PassthroughPathPrefix + as
}

// Client is an HTTP client that calls as DefaultViewer.
func (s *Solution) Client() *http.Client { return s.ClientAs(DefaultViewer) }

// ClientAs is an HTTP client that calls as viewer: the bearer, and the
// identity headers the gateway would stamp, replacing any the request sets.
// An empty field sends no header, as for a viewer the gateway would stamp none
// for.
func (s *Solution) ClientAs(viewer Viewer) *http.Client {
	return &http.Client{Transport: viewerTransport{viewer: viewer, base: s.server.Client().Transport}}
}

type viewerTransport struct {
	viewer Viewer
	base   http.RoundTripper
}

func (t viewerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for header, value := range map[string]string{
		"authorization": t.viewer.Bearer,
		"x-org-id":      t.viewer.OrgID,
		"x-session-id":  t.viewer.SessionID,
	} {
		r.Header.Del(header)
		if value != "" {
			r.Header.Set(header, value)
		}
	}
	return t.base.RoundTrip(r)
}

// capability is a stand-in issuer's capability, minted per seed.
//
// It is minted by **core's** authority, from core's own conformance fixture
// identities and key — the one implementation of a Work Context, which this
// runtime neither signs nor parses. The private key is public by design (core
// derives it from a seed in its own source), so this is a real sealed
// capability that a conforming verifier accepts, without a signer or a payload
// struct living here. That matters beyond convenience: a fixture issuer with
// its own encoding is how two implementations of a capability format start.
//
// Memoised by seed so a test can recompute the capability it expects to have
// been presented: every mint carries a fresh nonce, so minting the same seed
// twice would otherwise produce two different strings.
func capability(seed string) string {
	capabilityMu.Lock()
	defer capabilityMu.Unlock()
	if issued, ok := issuedCapabilities[seed]; ok {
		return issued
	}
	token, _, err := standInAuthority().Start(context.Background(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             seed,
		Audience:           corework.FixtureAudience,
		OrganizationID:     corework.FixtureOrganization,
		InstallationID:     corework.FixtureInstallation,
		TTL:                10 * time.Minute,
	})
	if err != nil {
		panic("stand-in capability: " + err.Error())
	}
	issuedCapabilities[seed] = token
	return token
}

var (
	capabilityMu       sync.Mutex
	issuedCapabilities = map[string]string{}
)

// standInAuthority is core's minter, configured from core's fixture identities.
//
// Built once through sync.OnceValue rather than on a nil check: the check was a
// data race, reached from the fake host's mint handler and from capability() at
// the same time, so a consumer running this seam under -race could fail in a
// file they do not own, for a reason that has nothing to do with their test.
var standInAuthority = sync.OnceValue(func() *corework.Authority {
	_, key := corework.FixtureKeyPair()
	return &corework.Authority{
		Issuer:    corework.FixtureIssuer,
		KeyID:     corework.FixtureKeyID,
		Key:       key,
		Revisions: corework.FixtureRevisions(),
		Seals:     corework.FixtureSeals(),
	}
})
