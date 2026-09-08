// Package solution is a generic runtime for "solution" modules — independently
// deployed extensions that plug into a host at runtime with no build-time
// coupling. It owns everything every solution needs identically: env/config,
// self-registration with the host and the gateway (with a heartbeat), CORS,
// static Module Federation asset serving, the capability handshake, and the
// solution manifest. A solution author supplies a manifest and one or more
// handlers; each handler receives a Gateway that forwards the caller's bearer.
//
// This package depends on nothing but the standard library and knows nothing
// about any specific host or solution.
package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
)

// Manifest is the small, solution-specific description the author provides.
type Manifest struct {
	ID            string   // logical id / gateway service alias, e.g. "lastlogin-go"
	Title         string   // nav title, e.g. "Last Login · GO"
	Order         int      // nav order
	ExposedModule string   // MF exposed module (default "./Page")
	Contract      string   // capability contract id (default: ID)
	Capabilities  []string // capability feature ids
	// Dashboard is an optional data-graph (events / metrics / dashboards, per
	// @codefly/saas-plugin-manifest's DataGraph) the host renders. The runtime
	// carries it verbatim and never interprets it: the graph's schema and its
	// validation are owned by the host, so this stays an opaque declaration to
	// keep the runtime host-agnostic.
	Dashboard any
}

// Handler is a solution endpoint. It receives a Gateway bound to the caller's
// bearer and returns any JSON-serializable value (or an error → 502).
type Handler func(ctx context.Context, gw *Gateway) (any, error)

// Server wires a manifest and handlers into a running solution.
type Server struct {
	manifest Manifest
	handlers map[string]Handler
	cfg      config
}

type config struct {
	port, publicURL, gatewayURL string
	hostRegisterURL             string
	gatewayRegisterURL          string
	moduleRegisterURL           string
	selfUpstream, assetsDir     string
	internalToken               string
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// address returns a resolved endpoint's "scheme://host:port", or "" if the SDK
// could not resolve it. Using the SDK keeps addresses and ports out of the
// runtime: they come from Codefly's runtime-injected endpoint map (or, in a
// local run, its deterministic native workspace map) — never a hardcoded port.
func address(ctx context.Context, module, service, endpoint, api string) string {
	q := codefly.For(ctx).Endpoint(endpoint)
	if module != "" {
		q = q.Module(module)
	}
	if service != "" {
		q = q.Service(service)
	}
	if api != "" {
		q = q.API(api)
	}
	if ni := q.NetworkInstance(); ni != nil {
		return ni.Address
	}
	return ""
}

// endpointKey normalizes a name into the segment Codefly uses in an endpoint
// environment variable: upper-cased, dashes to underscores.
func endpointKey(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}

// discoverHostModule finds the single host module that owns a role
// (service+endpoint+api), so host resolution never depends on the host's
// workspace module name. It returns the owning module, or "" when the role is
// unresolved or ambiguous — an empty result makes loadConfig leave the address
// empty so validate() fails loud at boot rather than the runtime silently
// picking an arbitrary host.
//
// Deployed under the runtime, Codefly injects each resolved endpoint as
// CODEFLY__ENDPOINT__<MODULE>__<SERVICE>__<ENDPOINT>__<API>, so scanning the
// injected carriers for the role suffix yields the owning module segment. Run
// locally there are no injected carriers, so the workspace on disk is the source
// of truth: we find the unique module declaring a service of that name — the same
// resolution the SDK's native map performs. Either way more than one distinct
// owner is genuinely ambiguous and resolves to "" (see codefly-dev/core#382).
func discoverHostModule(ctx context.Context, service, endpoint, api string) string {
	prefix := resources.EndpointPrefix + "__"
	suffix := "__" + endpointKey(service) + "__" + endpointKey(endpoint) + "__" + endpointKey(api)
	found := ""
	for _, kv := range os.Environ() {
		key, value, ok := strings.Cut(kv, "=")
		if !ok || value == "" {
			continue
		}
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, suffix) {
			continue
		}
		// The single segment between the prefix and the role suffix is the host
		// module; a longer service name would leave "__" in it and must not match.
		mod := strings.TrimSuffix(strings.TrimPrefix(key, prefix), suffix)
		if mod == "" || strings.Contains(mod, "__") {
			continue
		}
		if found != "" && found != mod {
			return "" // two host modules own the same role: ambiguous
		}
		found = mod
	}
	if found != "" {
		return found
	}
	// No injected carrier (local run): resolve the owning module from the
	// workspace on disk. FindUniqueServiceAndModuleByName returns an error when
	// the service name is not unique across modules, which we treat as ambiguous.
	ws, err := resources.FindWorkspaceUp(ctx)
	if err != nil || ws == nil {
		return ""
	}
	svc, err := ws.FindUniqueServiceAndModuleByName(ctx, service)
	if err != nil || svc == nil {
		return ""
	}
	return svc.Module
}

// hostAddress resolves a host endpoint by its role. With an explicit module it
// scopes to that module. With the module unset it discovers the single module
// owning the role (see discoverHostModule) and then resolves the concrete
// address through the SDK, so both deployed and local-native runs resolve the
// host identically — the host's workspace name/alias is irrelevant, with no
// CODEFLY_HOST_MODULE coupling and no hardcoded list of known host names.
func hostAddress(ctx context.Context, module, service, endpoint, api string) string {
	if module == "" {
		if module = discoverHostModule(ctx, service, endpoint, api); module == "" {
			return ""
		}
	}
	return address(ctx, module, service, endpoint, api)
}

// resolveGateway resolves the host gateway's rest endpoint by role, independent of
// the host module's name (see hostAddress). saas-starter renamed this service
// auth-sidecar → auth-gateway (v0.0.49); when the current name resolves empty we
// retry the old one so a solution boots against either host version.
func resolveGateway(ctx context.Context, module, gateway string) string {
	if addr := hostAddress(ctx, module, gateway, "rest", "rest"); addr != "" {
		return addr
	}
	if gateway == "auth-gateway" {
		if addr := hostAddress(ctx, module, "auth-sidecar", "rest", "rest"); addr != "" {
			return addr
		}
	}
	return ""
}

// resolveFrontend resolves the host frontend's http endpoint by role, like
// resolveGateway — host-module-name-agnostic.
func resolveFrontend(ctx context.Context, module, frontend string) string {
	return hostAddress(ctx, module, frontend, "http", "http")
}

// loadConfig resolves every address, port, and secret through the Codefly SDK
// so nothing is hardcoded. The host it plugs into is named by Codefly-convention
// roles (overridable), and their concrete addresses are resolved from the SDK —
// the same source `codefly endpoint` and the host services themselves use.
func loadConfig(ctx context.Context, id string) config {
	// Empty by default: the host is resolved by service+endpoint role, not by its
	// workspace module name (see resolveGateway). An explicit CODEFLY_HOST_MODULE
	// scopes the lookup only when a composition is genuinely ambiguous.
	hostModule := env("CODEFLY_HOST_MODULE", "")
	hostFrontend := env("CODEFLY_HOST_FRONTEND", "frontend")
	hostGateway := env("CODEFLY_HOST_GATEWAY", "auth-gateway")

	// Own endpoint: the port Codefly assigned this service, not a fixed default.
	port := env("PORT", "")
	if port == "" {
		if self := address(ctx, "", "", "http", "http"); self != "" {
			if u, err := url.Parse(self); err == nil {
				port = u.Port()
			}
		}
	}
	public := env("PUBLIC_URL", "")
	if public == "" {
		public = "http://localhost:" + port
	}

	// Host endpoints, resolved via the SDK (no localhost:port literals).
	gatewayURL := strings.TrimRight(env("GATEWAY_URL", resolveGateway(ctx, hostModule, hostGateway)), "/")
	frontendURL := strings.TrimRight(resolveFrontend(ctx, hostModule, hostFrontend), "/")

	// Internal token: the namespaced workspace secret Codefly injects, resolved
	// by name through the SDK rather than a bare os.Getenv the runtime never sees.
	token := env("CODEFLY_INTERNAL_TOKEN", "")
	if token == "" {
		token, _ = codefly.For(ctx).WorkspaceSecret("internal-auth", "CODEFLY_INTERNAL_TOKEN")
	}

	return config{
		port:               port,
		publicURL:          public,
		gatewayURL:         gatewayURL,
		hostRegisterURL:    env("HOST_REGISTER_URL", frontendURL+"/api/solutions/register"),
		gatewayRegisterURL: env("GATEWAY_REGISTER_URL", gatewayURL+"/solutions/_register"),
		moduleRegisterURL:  env("GATEWAY_MODULE_REGISTER_URL", gatewayURL+"/modules/_register"),
		selfUpstream:       env("SELF_UPSTREAM", public),
		assetsDir:          env("ASSETS_DIR", "../fe-remote/dist"),
		internalToken:      token,
	}
}

// validate rejects a config the runtime cannot actually serve or register with.
// When neither the SDK nor an explicit env override resolves a value, loadConfig
// leaves it empty; without this check Serve would bind ":"+"" — which the kernel
// happily accepts as a random port — and POST registrations to scheme-less URLs
// like "/solutions/_register" that http.Client.Do rejects and the heartbeat then
// retries forever in silence. Both are the exact silent no-op this whole SDK
// resolution effort exists to eliminate, so an unresolved config must fail loud
// at boot rather than come up looking healthy on the wrong port.
func (c config) validate() error {
	if p, err := strconv.Atoi(c.port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("unresolved listen port %q: set PORT or ensure the SDK resolves this service's http endpoint", c.port)
	}
	for name, raw := range map[string]string{
		"gateway URL":          c.gatewayURL,
		"host register URL":    c.hostRegisterURL,
		"gateway register URL": c.gatewayRegisterURL,
		"module register URL":  c.moduleRegisterURL,
	} {
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Host == "" {
			return fmt.Errorf("unresolved %s %q: the SDK could not resolve the host endpoint and no explicit override was set", name, raw)
		}
	}
	return nil
}

// New starts a solution builder for the given manifest.
func New(manifest Manifest) *Server {
	if manifest.ExposedModule == "" {
		manifest.ExposedModule = "./Page"
	}
	if manifest.Contract == "" {
		manifest.Contract = "lastlogin"
	}
	return &Server{manifest: manifest, handlers: make(map[string]Handler)}
}

// Handle registers a solution endpoint. Chainable.
func (s *Server) Handle(path string, handler Handler) *Server {
	s.handlers[path] = handler
	return s
}

// Serve reads env config, self-registers, and blocks serving the solution.
func (s *Server) Serve() error {
	ctx := context.Background()
	// The SDK owns environment resolution: load Codefly's injected carriers so
	// endpoint and workspace-secret lookups resolve from them (falling back to
	// the local native workspace map when not running under the runtime).
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		log.Printf("codefly: load environment: %v", err)
	}
	s.cfg = loadConfig(ctx, s.manifest.ID)
	if err := s.cfg.validate(); err != nil {
		return fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	ln, err := net.Listen("tcp", ":"+s.cfg.port)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// serve wires the routes, starts the host and gateway registration heartbeats,
// and serves on ln until ctx is cancelled. Split from Serve so a test can boot a
// real solution on an ephemeral listener and exercise the whole registration and
// manifest path.
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/solution.json", withCORS(s.handleManifest))
	mux.HandleFunc("/.well-known/capabilities", withCORS(s.handleCapabilities))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for path, handler := range s.handlers {
		mux.HandleFunc(path, withCORS(s.wrap(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/",
		withCORSHandler(http.FileServer(http.Dir(s.cfg.assetsDir)))))

	manifestBody, _ := json.Marshal(s.manifestMap())
	upstreamBody, _ := json.Marshal(map[string]string{"id": s.manifest.ID, "upstream": s.cfg.selfUpstream})
	go s.heartbeat(ctx, s.cfg.hostRegisterURL, manifestBody, "host")
	go s.heartbeat(ctx, s.cfg.gatewayRegisterURL, upstreamBody, "gateway")
	s.registerConsumedAPIs(ctx)

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	log.Printf("solution %q listening on :%s (gateway=%s)", s.manifest.ID, s.cfg.port, s.cfg.gatewayURL)
	if serveErr := srv.Serve(ln); !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// registerConsumedAPIs registers each of the solution's api.consumes targets
// with the gateway so it can proxy /v1/<prefix>/* to the consumed module. The
// targets are projected by core into CODEFLY__API_CONSUMES; the address of each
// is already injected (the backend depends on the consumed service), so it is
// resolved through the SDK exactly as the gateway and frontend are. Each target
// gets its own heartbeat, mirroring the host and gateway registrations, so a
// registration that is briefly unavailable at boot is retried.
//
// A solution that declares no api.consumes has an empty CODEFLY__API_CONSUMES
// and registers nothing — no behavior changes unless api.consumes is declared.
func (s *Server) registerConsumedAPIs(ctx context.Context) {
	consumed, err := manifest.ParseConsumedAPIs(os.Getenv(manifest.APIConsumesEnvironmentVariable))
	if err != nil {
		// A malformed projection is a build-time/CLI defect the runtime cannot
		// repair. ParseConsumedAPIs returns no entries on a decode error, so this
		// registers nothing at all: every consumed facade silently 404s at the
		// gateway. Crashing would also take down this solution's own frontend, so
		// serve on — but log loudly, because this line is the only signal that the
		// entire api.consumes federation was dropped.
		log.Printf("solution %q: api.consumes federation disabled: %v", s.manifest.ID, err)
	}
	for _, c := range consumed {
		// The gateway proxies /v1/<As>/*, where As is the facade entry-point core
		// derives from the producing endpoint's proto package (the last non-version
		// segment) — not the module name. The runtime cannot reconstruct that
		// default from the projected identity, so an entry that reached us without
		// an explicit As is one the CLI should have resolved: registering a guessed
		// prefix (e.g. the module name) would proxy a route the generated client
		// never calls (a silent 404) and could even claim a prefix meant for a
		// different facade. Skip it loudly instead of guessing.
		if c.As == "" {
			log.Printf("solution %q: consumed api %s/%s/%s has no facade entry-point (as); skipping gateway module registration",
				s.manifest.ID, c.Module, c.Service, c.Endpoint)
			continue
		}
		prefix := c.As
		upstream := address(ctx, c.Module, c.Service, c.Endpoint, c.Protocol)
		if upstream == "" {
			// The address is injected because the backend depends on the consumed
			// service; if it did not resolve, registering an empty upstream would
			// only be rejected, so skip loudly instead.
			log.Printf("solution %q: no upstream resolved for consumed api %q (%s/%s/%s); skipping gateway module registration",
				s.manifest.ID, prefix, c.Module, c.Service, c.Endpoint)
			continue
		}
		body, _ := json.Marshal(map[string]string{"prefix": prefix, "upstream": upstream})
		go s.heartbeat(ctx, s.cfg.moduleRegisterURL, body, "gateway module "+prefix)
	}
}

func (s *Server) manifestMap() map[string]any {
	m := map[string]any{
		"id":  s.manifest.ID,
		"nav": map[string]any{"title": s.manifest.Title, "path": "/s/" + s.manifest.ID, "order": s.manifest.Order},
		"frontend": map[string]any{
			"type":          "module-federation",
			"manifestUrl":   s.cfg.publicURL + "/assets/mf-manifest.json",
			"exposedModule": s.manifest.ExposedModule,
			"reactRange":    "^19",
		},
		"backend": map[string]any{"serviceAlias": s.manifest.ID, "capabilityPath": "/.well-known/capabilities"},
	}
	// Only emit the slot when declared: a null dashboard would break a host that
	// feeds a present slot straight into its data-graph validator, and it keeps
	// the wire byte-identical for solutions that declare no dashboard.
	if s.manifest.Dashboard != nil {
		m["dashboard"] = s.manifest.Dashboard
	}
	return m
}

func (s *Server) handleManifest(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.manifestMap())
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": 1,
		"contract":      s.manifest.Contract,
		"contractMajor": 1,
		"capabilities":  s.manifest.Capabilities,
	})
}

func (s *Server) wrap(handler Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("authorization")
		if bearer == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer"})
			return
		}
		result, err := handler(r.Context(), &Gateway{baseURL: s.cfg.gatewayURL, bearer: bearer})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (s *Server) heartbeat(ctx context.Context, url string, body []byte, label string) {
	lastStatus := 0
	lastErr := ""
	for {
		status, err := s.beat(ctx, url, body)
		switch {
		case err != nil:
			// A shutdown cancels the in-flight request; that error is expected,
			// not a registration failure, so don't log it.
			if ctx.Err() != nil {
				return
			}
			// Transport/URL errors (connection refused, scheme-less URL) never
			// surface a status. Left unlogged they made a permanently-failing
			// registration indistinguishable from a working one. Throttle to one
			// line per distinct error so a persistent outage doesn't spam.
			if msg := err.Error(); msg != lastErr {
				log.Printf("registration with %s failed for %q: %v", label, s.manifest.ID, err)
				lastErr, lastStatus = msg, 0
			}
		case status != lastStatus:
			if status < 300 {
				log.Printf("registered with %s as %q", label, s.manifest.ID)
			} else {
				log.Printf("registration with %s rejected (status %d) for %q", label, status, s.manifest.ID)
			}
			lastStatus, lastErr = status, ""
		default:
			lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}

// beat performs one registration POST and returns the HTTP status, or an error
// if the request could not be built or the round trip failed.
func (s *Server) beat(ctx context.Context, url string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("content-type", "application/json")
	if s.cfg.internalToken != "" {
		req.Header.Set("x-codefly-internal-token", s.cfg.internalToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// Gateway is a client bound to the caller's bearer. It exposes an HTTP client
// that forwards that bearer and the gateway base URL, so a solution can drive
// its own generated SDK against the gateway — every call stays authenticated
// and routed through the gateway.
type Gateway struct {
	baseURL string
	bearer  string
}

func (g *Gateway) BaseURL() string { return g.baseURL }

// HTTPClient returns an http.Client that injects the caller's bearer on every
// request. Satisfies connect.HTTPClient. Advanced escape hatch — prefer Unary.
func (g *Gateway) HTTPClient() *http.Client {
	return &http.Client{Transport: bearerTransport{bearer: g.bearer, base: http.DefaultTransport}}
}

// Unary makes a typed Connect call to a fully-qualified procedure through the
// gateway. Req and Resp are generated protobuf messages; the gateway URL, the
// bearer, and the wire protocol are hidden so a handler only names a procedure
// and passes typed messages — the twin of the Python runtime's gateway.unary.
func Unary[Req, Resp any](ctx context.Context, gw *Gateway, procedure string, req *Req) (*Resp, error) {
	client := connect.NewClient[Req, Resp](gw.HTTPClient(), gw.baseURL+procedure)
	resp, err := client.CallUnary(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

type bearerTransport struct {
	bearer string
	base   http.RoundTripper
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("authorization", t.bearer)
	return t.base.RoundTrip(r)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

func withCORSHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setCORS(w)
		next.ServeHTTP(w, r)
	})
}

func setCORS(w http.ResponseWriter) {
	w.Header().Set("access-control-allow-origin", "*")
	w.Header().Set("access-control-allow-headers", "authorization, content-type")
	w.Header().Set("access-control-allow-methods", "GET, POST, OPTIONS")
}
