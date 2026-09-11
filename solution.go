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
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/google/uuid"
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

// RequestHandler receives the incoming request and the same caller-bound Gateway
// as Handler. Implementations must bound and validate request bodies before use.
// Errors use the runtime's normal JSON error response.
type RequestHandler func(r *http.Request, gw *Gateway) (any, error)

// Server wires a manifest and handlers into a running solution.
type Server struct {
	manifest Manifest
	handlers map[string]RequestHandler
	cfg      config
	// registrationInterval is how long a registration heartbeat waits between
	// beats. Zero means defaultRegistrationInterval. Per-server rather than a
	// package value so a test can drive several beats without every other
	// server in the process — including the heartbeat goroutines a finished
	// test has not yet unwound — reading the same variable.
	registrationInterval time.Duration
}

type config struct {
	port, publicURL, gatewayURL string
	hostRegisterURL             string
	gatewayRegisterURL          string
	moduleRegisterURL           string
	moduleTokenURL              string
	// solutionTokenURL is the gateway exchange that mints this solution's own
	// registration credential (see solutionCredential).
	solutionTokenURL        string
	selfUpstream, assetsDir string
	internalToken           string
	// solutionSecret is the registration secret the composition provisioned for
	// this solution — the plaintext twin of the digest the host declares for its
	// id. Empty when the composition provisioned none.
	solutionSecret string
	// moduleSecrets maps a consumed module's facade prefix to the registration
	// secret the composition provisioned for it.
	moduleSecrets map[string]string
	// registrationInterval is the beat period an operator chose, or zero for
	// defaultRegistrationInterval; registrationIntervalErr is why an explicit
	// one was not usable.
	registrationInterval    time.Duration
	registrationIntervalErr error
	// environmentLoadErr is the failure, if any, of loading Codefly's injected
	// carriers. Every SDK-resolved value below is empty when that load failed,
	// so validate() must say so rather than report each empty value as
	// something the composition forgot to provision.
	environmentLoadErr error
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

	// Both module-federation endpoints live on one gateway: the exchange mints the
	// credential the registration presents, so pointing registration at another
	// gateway while the exchange stayed on this one would mint against one host
	// and register with a second that never trusts the result.
	moduleRegisterURL := env("GATEWAY_MODULE_REGISTER_URL", gatewayURL+moduleRegisterPath)

	// Internal token: the namespaced workspace secret Codefly injects, resolved
	// by name through the SDK rather than a bare os.Getenv the runtime never sees.
	token := env("CODEFLY_INTERNAL_TOKEN", "")
	if token == "" {
		token, _ = codefly.For(ctx).WorkspaceSecret("internal-auth", "CODEFLY_INTERNAL_TOKEN")
	}

	// The solution's own registration exchange lives on the same gateway as its
	// registration, for the reason the module pair does: the token minted by one
	// gateway is trusted by that gateway's host, not by another's.
	gatewayRegisterURL := env("GATEWAY_REGISTER_URL", gatewayURL+solutionRegisterPath)

	cfg := config{
		port:               port,
		publicURL:          public,
		gatewayURL:         gatewayURL,
		hostRegisterURL:    env("HOST_REGISTER_URL", frontendURL+"/api/solutions/register"),
		gatewayRegisterURL: gatewayRegisterURL,
		moduleRegisterURL:  moduleRegisterURL,
		moduleTokenURL:     env("GATEWAY_MODULE_REGISTRATION_TOKEN_URL", siblingURL(moduleRegisterURL, moduleRegisterPath, moduleRegistrationTokenPath)),
		solutionTokenURL:   env("GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL", siblingURL(gatewayRegisterURL, solutionRegisterPath, solutionRegistrationTokenPath)),
		selfUpstream:       env("SELF_UPSTREAM", public),
		assetsDir:          env("ASSETS_DIR", "../fe-remote/dist"),
		internalToken:      token,
		solutionSecret:     solutionRegistrationSecret(ctx),
		moduleSecrets:      parseModuleRegistrationSecrets(env(ModuleRegistrationSecretsEnvironmentVariable, "")),
	}
	cfg.registrationInterval, cfg.registrationIntervalErr = registrationIntervalFromEnv()
	return cfg
}

// RegistrationIntervalEnvironmentVariable sets how long a registration
// heartbeat waits between beats, as a Go duration ("30s", "2m").
//
// It exists because a beat stopped being free. Each self-registration beat now
// runs a credential exchange whose every success is an audited mint on the
// issuer — at the 15s default, two surfaces, that is ~11.5k audited mints per
// solution per day, and the figure scales with the number of solutions. The
// right value is whatever the host's registration TTL allows, which this
// runtime cannot observe, so the default is unchanged and the lever belongs to
// whoever knows both numbers.
const RegistrationIntervalEnvironmentVariable = "CODEFLY__SOLUTION_REGISTRATION_INTERVAL"

// registrationIntervalMinimum floors an explicit interval. Below this the beat
// costs more in audited mints than any freshness it buys, and a typo ("100"
// parsed as 100ns) would otherwise turn the heartbeat into a mint loop.
const registrationIntervalMinimum = time.Second

// registrationIntervalFromEnv reads an explicit beat period. It returns zero
// for "unset", and an error — never a silent fallback — for a value that is set
// but unusable, because an operator who asked for a slower beat to bound their
// mint rate must not get the fast default because of a typo.
func registrationIntervalFromEnv() (time.Duration, error) {
	raw := env(RegistrationIntervalEnvironmentVariable, "")
	if raw == "" {
		return 0, nil
	}
	interval, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("unparseable %s %q: want a Go duration such as %q or %q: %w",
			RegistrationIntervalEnvironmentVariable, raw, "30s", "2m", err)
	}
	if interval < registrationIntervalMinimum {
		return 0, fmt.Errorf("%s %q is below the %s minimum: a beat this fast mints a registration token per surface per beat, each an audited event on the issuer",
			RegistrationIntervalEnvironmentVariable, raw, registrationIntervalMinimum)
	}
	return interval, nil
}

// solutionRegistrationSecret resolves the registration secret the composition
// provisioned for this solution: an explicit environment override first, then
// the namespaced workspace secret Codefly injects — resolved by name through the
// SDK, exactly as the cluster-internal token is, so the same declaration serves
// a local `codefly run` and a deployed cell. Empty means none resolved.
//
// The SDK's error is dropped because it carries no information: WorkspaceSecret
// returns the same "no workspace configuration value" error whether the group
// was never declared or the carriers it lives in never loaded. The one signal
// that does distinguish them is whether loading the environment failed at all,
// which Serve records in config.environmentLoadErr for validate() to report.
func solutionRegistrationSecret(ctx context.Context) string {
	if secret := env(SolutionRegistrationSecretEnvironmentVariable, ""); secret != "" {
		return trimmedSecret(secret)
	}
	secret, _ := codefly.For(ctx).WorkspaceSecret(SolutionRegistrationSecretGroup, SolutionRegistrationSecretKey)
	return trimmedSecret(secret)
}

// trimmedSecret strips the whitespace a secret store puts around a value —
// above all the trailing newline a file-mounted or `echo`-generated secret
// almost always carries.
//
// This is not cosmetic. The secret is sent as an HTTP header value, and net/http
// refuses to write a header containing a newline: the request never leaves the
// process, so the beat fails with "invalid header field value" on every attempt,
// forever, while validate() saw a non-empty secret and let the boot through. The
// registration silently never happens for a reason no amount of checking the
// provisioning would reveal, because the provisioning is in fact correct.
func trimmedSecret(secret string) string {
	return strings.TrimSpace(secret)
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
	required := map[string]string{
		"gateway URL":          c.gatewayURL,
		"host register URL":    c.hostRegisterURL,
		"gateway register URL": c.gatewayRegisterURL,
		"module register URL":  c.moduleRegisterURL,
		"module token URL":     c.moduleTokenURL,
		"solution token URL":   c.solutionTokenURL,
	}
	// A token URL is not resolved from the SDK at all: it is derived from its
	// register URL by siblingURL, which yields "" for a base it cannot pair.
	// Reported with the generic message below, that sent an operator looking at
	// SDK endpoint resolution for a value their own override had broken — and
	// the override is a variable whose shape only started mattering when the
	// exchange began deriving from it, so a deployment that booted yesterday
	// can stop booting today with no mention of the variable that changed.
	unpairable := map[string]string{
		"module token URL":   "GATEWAY_MODULE_REGISTER_URL must end in " + moduleRegisterPath + " for its exchange to be derived from it; set GATEWAY_MODULE_REGISTRATION_TOKEN_URL explicitly otherwise",
		"solution token URL": "GATEWAY_REGISTER_URL must end in " + solutionRegisterPath + " for its exchange to be derived from it; set GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL explicitly otherwise",
	}
	for name, raw := range required {
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Host == "" {
			if c.environmentLoadErr != nil {
				return fmt.Errorf("unresolved %s %q, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
					name, raw, c.environmentLoadErr)
			}
			if hint, ok := unpairable[name]; ok && raw == "" {
				return fmt.Errorf("unresolved %s: %s", name, hint)
			}
			return fmt.Errorf("unresolved %s %q: the SDK could not resolve the host endpoint and no explicit override was set", name, raw)
		}
	}
	if c.registrationIntervalErr != nil {
		return c.registrationIntervalErr
	}
	if c.solutionSecret == "" {
		// An empty secret has two causes that look identical here, and sending
		// the operator to provision a secret that is already provisioned is the
		// worse of the two mistakes — so when the environment never loaded, say
		// that instead of naming the provisioning.
		if c.environmentLoadErr != nil {
			return fmt.Errorf("no solution registration secret resolved, and loading Codefly's injected environment failed first: %w — the secret may well be provisioned; fix the environment load before treating this as missing provisioning",
				c.environmentLoadErr)
		}
		// The host admits a registration only against a credential minted from
		// this secret; without it every beat is a guaranteed refusal, so the
		// boot fails here, naming the provisioning, rather than coming up
		// looking healthy while nothing is served.
		return fmt.Errorf("no solution registration secret provisioned: set %s, or provision the workspace secret %s/%s and declare that group as a workspace-configuration dependency of this backend",
			SolutionRegistrationSecretEnvironmentVariable, SolutionRegistrationSecretGroup, SolutionRegistrationSecretKey)
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
	return &Server{manifest: manifest, handlers: make(map[string]RequestHandler)}
}

// Handle registers a solution endpoint. Chainable.
func (s *Server) Handle(path string, handler Handler) *Server {
	return s.HandleRequest(path, func(r *http.Request, gw *Gateway) (any, error) {
		return handler(r.Context(), gw)
	})
}

// HandleRequest registers an endpoint that consumes request input. It uses the
// same bearer forwarding, organisation binding and CORS as Handle.
func (s *Server) HandleRequest(path string, handler RequestHandler) *Server {
	s.handlers[path] = handler
	return s
}

// Serve reads env config, self-registers, and blocks serving the solution.
func (s *Server) Serve() error {
	ctx := context.Background()
	// The SDK owns environment resolution: load Codefly's injected carriers so
	// endpoint and workspace-secret lookups resolve from them (falling back to
	// the local native workspace map when not running under the runtime).
	// Kept, not swallowed: when this fails every SDK-resolved endpoint and
	// secret below comes back empty, and validate() would otherwise report each
	// one as something the composition forgot to provision.
	environmentLoadErr := codefly.LoadEnvironmentVariables()
	if environmentLoadErr != nil {
		log.Printf("codefly: load environment: %v", environmentLoadErr)
	}
	s.cfg = loadConfig(ctx, s.manifest.ID)
	s.cfg.environmentLoadErr = environmentLoadErr
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
		mux.HandleFunc(path, withCORS(s.wrapRequest(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/",
		withCORSHandler(http.FileServer(http.Dir(s.cfg.assetsDir)))))

	manifestBody, _ := json.Marshal(s.manifestMap())
	upstreamBody, _ := json.Marshal(map[string]string{"id": s.manifest.ID, "upstream": s.cfg.selfUpstream})
	go s.heartbeat(ctx, s.cfg.hostRegisterURL, manifestBody, "host", s.newSolutionCredential())
	go s.heartbeat(ctx, s.cfg.gatewayRegisterURL, upstreamBody, "gateway", s.newSolutionCredential())
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
		secret := s.cfg.moduleSecrets[prefix]
		if secret == "" {
			// The gateway admits a registration only against a token signed by
			// accounts, and accounts issues one only to a caller holding the
			// secret whose digest the composition declared for this prefix.
			// Without it every beat would be a guaranteed 401, so skip loudly:
			// this line is the signal that provisioning, not the runtime, is the
			// missing half.
			log.Printf("solution %q: no registration secret provisioned for consumed api %q (%s); skipping gateway module registration",
				s.manifest.ID, prefix, ModuleRegistrationSecretsEnvironmentVariable)
			continue
		}
		body, _ := json.Marshal(map[string]string{"prefix": prefix, "upstream": upstream})
		credential := &moduleCredential{
			tokenURL:      s.cfg.moduleTokenURL,
			internalToken: s.cfg.internalToken,
			prefix:        prefix,
			secret:        secret,
		}
		go s.heartbeat(ctx, s.cfg.moduleRegisterURL, body, "gateway module "+prefix, credential)
	}
}

// newSolutionCredential builds one self-registration credential. Each
// heartbeat gets its own, because a solutionCredential is not safe to share:
// its refusal and mint bookkeeping is written on every beat with no locking,
// so two goroutines holding one would race on those fields. (Sharing would not
// cause two beats to present the same token — nothing is cached, so each
// authorize mints its own — which is why the fields, not the token, are the
// reason.) validate() has already refused a boot without a secret; there is no
// other credential to present.
func (s *Server) newSolutionCredential() *solutionCredential {
	return &solutionCredential{
		tokenURL:      s.cfg.solutionTokenURL,
		internalToken: s.cfg.internalToken,
		id:            s.manifest.ID,
		secret:        s.cfg.solutionSecret,
	}
}

// solutionManifestSchemaMajor and solutionHostContractMajor are the majors
// this runtime's manifest and page contract are built against. The host checks
// both before activating a remote, and treats a silent manifest as 1 — so these
// say out loud what silence would assert, and become the place to bump when the
// runtime moves to a newer host contract.
const (
	solutionManifestSchemaMajor = 1
	solutionHostContractMajor   = 1
)

func (s *Server) manifestMap() map[string]any {
	m := map[string]any{
		"id":            s.manifest.ID,
		"schemaVersion": solutionManifestSchemaMajor,
		"nav":           map[string]any{"title": s.manifest.Title, "path": "/s/" + s.manifest.ID, "order": s.manifest.Order},
		"frontend": map[string]any{
			"type":          "module-federation",
			"manifestUrl":   s.cfg.publicURL + "/assets/mf-manifest.json",
			"exposedModule": s.manifest.ExposedModule,
			"hostContract":  solutionHostContractMajor,
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
	// The same majors the registration manifest declares, from the same
	// constants. Hardcoded here, a bump of either constant would leave this
	// document announcing the old major while the manifest announced the new
	// one, and a host that checks both would see one solution claiming two
	// different contracts.
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": solutionManifestSchemaMajor,
		"contract":      s.manifest.Contract,
		"contractMajor": solutionHostContractMajor,
		"capabilities":  s.manifest.Capabilities,
	})
}

func (s *Server) wrap(handler Handler) http.HandlerFunc {
	return s.wrapRequest(func(r *http.Request, gw *Gateway) (any, error) {
		return handler(r.Context(), gw)
	})
}

func (s *Server) wrapRequest(handler RequestHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("authorization")
		if bearer == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer"})
			return
		}
		result, err := handler(r, newGateway(s.cfg.gatewayURL, bearer, r.Header.Get(orgHeader)))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (s *Server) heartbeat(ctx context.Context, url string, body []byte, label string, auth registrationAuth) {
	interval := s.registrationInterval
	if interval == 0 {
		interval = s.cfg.registrationInterval
	}
	if interval == 0 {
		interval = defaultRegistrationInterval
	}
	lastStatus := 0
	lastDetail := ""
	lastErr := ""
	// detailsLogged counts the distinct reasons reported for the current status.
	// Reset whenever the status changes or a registration succeeds.
	detailsLogged := 0
	failures := 0
	for {
		status, detail, err := s.beat(ctx, url, body, auth)
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			// The credential we just presented was refused. Offer it for
			// dropping so the next beat obtains a fresh one instead of replaying
			// a token the issuer has stopped honouring for the rest of its
			// lifetime. Whether that actually helps is the credential's call:
			// re-obtaining one it has just obtained cannot fix a refusal that
			// was never about staleness (see moduleCredential.invalidate).
			// 403 counts too — a gateway that answers "forbidden" to a lapsed
			// token would otherwise have it replayed for the rest of its life.
			auth.invalidate()
		}
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
				lastErr, lastStatus, lastDetail = msg, 0, ""
			}
		// The reason is part of what was last reported, not just the status. A
		// host that keeps answering 409 while changing why — one incompatibility
		// resolved, a second one now named — would otherwise say it once and go
		// silent on every reason after it, which is precisely the information
		// detail was plumbed through beat to carry.
		//
		// But the reason is text the *host* chooses, so it is not a key this
		// loop can trust to settle. A refusal that quotes something per-attempt
		// — the jti of the single-use token it just burned, a timestamp, a
		// request id — differs on every beat by construction, and keyed on that
		// alone the throttle is defeated exactly when the registration is most
		// broken: one line per beat per surface, forever. So changed reasons are
		// reported, but only so many per status; past that the status must
		// change, or a registration must succeed, before reasons speak again.
		case status != lastStatus || (detail != lastDetail && detailsLogged < maxRefusalDetailsPerStatus):
			if status != lastStatus {
				detailsLogged = 0
			}
			switch {
			case status < 300:
				log.Printf("registered with %s as %q", label, s.manifest.ID)
			case detail != "":
				// The host says why. A refusal with reasons — an incompatible
				// runtime contract, an id another publisher owns — is actionable
				// only with them; the status alone sends whoever reads it to
				// check provisioning.
				detailsLogged++
				log.Printf("registration with %s rejected (status %d) for %q: %s", label, status, s.manifest.ID, detail)
				if detailsLogged == maxRefusalDetailsPerStatus {
					log.Printf("registration with %s for %q has now given %d different reasons for status %d; further reasons are suppressed until the status changes or a registration succeeds",
						label, s.manifest.ID, detailsLogged, status)
				}
			default:
				log.Printf("registration with %s rejected (status %d) for %q", label, status, s.manifest.ID)
			}
			lastStatus, lastDetail, lastErr = status, detail, ""
		default:
			lastErr = ""
		}
		// A beat that failed is retried further and further out. Every failure
		// on the credential path — a refused registration, a refused exchange,
		// a response this process cannot use — otherwise resolves to "run the
		// whole thing again in `interval`", which turns one broken deployment
		// into a mint (and an audited security event on the issuer) four times
		// a minute per module, for as long as the solution runs. Backing off
		// bounds that without ever giving up: the first success resets it.
		if err != nil || status >= 300 {
			failures++
		} else {
			failures = 0
			detailsLogged = 0
			auth.succeeded()
		}
		// Which cap applies depends on what the failure cost. A refusal means
		// the surface answered, so the exchange before it minted a token: that
		// is the audited-event rate the long cap exists to bound. A beat that
		// never got an answer at all (status 0: the exchange refused, the
		// gateway was unreachable, the round trip timed out) minted nothing and
		// costs the issuer nothing, and the long cap buys nothing for it while
		// charging the full price — this solution stays absent from a host that
		// may itself be perfectly healthy for the whole capped wait after the
		// dependency comes back. Those beats retry on the short cap.
		backoffCap := registrationBackoffCap
		if status == 0 {
			backoffCap = registrationUnreachedBackoffCap
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(jittered(backoff(interval, failures, backoffCap))):
		}
	}
}

// maxRefusalDetailsPerStatus bounds how many distinct host-supplied reasons are
// logged for one unchanging status. High enough that a host working through a
// list of incompatibilities is followed to the end; low enough that a reason
// varying on every beat cannot turn the log into a per-beat stream.
const maxRefusalDetailsPerStatus = 5

// registrationJitter is the fraction of a wait that is randomized. Every
// heartbeat is started in the same instant by serve and shares one interval, so
// without it the two self-registration credentials run their exchange in
// lockstep — two simultaneous mints for the same solution id, every beat, for
// the life of the process. A per-id rate limit or a coarse jti on the issuer
// turns that into a registration that flaps for a reason invisible from here,
// so the beats are spread rather than aligned.
const registrationJitter = 0.2

// jittered spreads a wait over [d, d+registrationJitter*d]. It only ever waits
// longer, never shorter: the backoff a failing beat earned is a floor, and
// shortening it would undo the request-rate bound it exists to impose.
func jittered(d time.Duration) time.Duration {
	spread := int64(float64(d) * registrationJitter)
	if spread <= 0 {
		return d
	}
	return d + time.Duration(rand.Int64N(spread))
}

// registrationBackoffCap bounds the retry interval of a registration the server
// answered with a refusal. Every such beat cost a mint — an audited event on the
// issuer — so this is the cap that bounds that rate: the cost of waiting is that
// a recovered gateway takes this long to see the module again, so it trades a
// bounded outage for a bounded mint rate rather than abandoning either.
const registrationBackoffCap = 2 * time.Minute

// registrationUnreachedBackoffCap bounds the retry interval of a beat that never
// reached the registration surface. Nothing was minted and nothing was audited,
// so the only thing the wait buys is not hammering a dependency that is already
// failing fast — which a beat every 30s achieves — while the thing it costs is
// paid by a surface that did nothing wrong. Both self-registrations now mint
// through the gateway, so a gateway restart fails the *host frontend*
// registration too; on the long cap the solution stayed missing from a healthy
// host's nav for up to that cap plus jitter after the gateway was back, which is
// a self-inflicted outage rather than a bounded one.
const registrationUnreachedBackoffCap = 30 * time.Second

// backoff returns how long to wait before the next beat after `failures`
// consecutive failed ones: the steady interval while healthy, doubling while
// broken, never past backoffCap.
//
// An interval a caller chose that is already longer than the cap is honoured
// as-is rather than shortened — a cap exists to slow retries down, so applying
// it to an interval already slower than itself would have a failing beat retry
// *sooner* than a healthy one. That mattered little while the only cap was two
// minutes; with registrationUnreachedBackoffCap at 30s it is reachable by any
// caller who chooses a slower beat.
func backoff(interval time.Duration, failures int, backoffCap time.Duration) time.Duration {
	if interval >= backoffCap {
		return interval
	}
	wait := interval
	for range failures {
		if wait >= backoffCap/2 {
			return backoffCap
		}
		wait *= 2
	}
	return wait
}

// defaultRegistrationInterval is how long a registration heartbeat waits
// between beats when neither the server nor
// RegistrationIntervalEnvironmentVariable names one.
const defaultRegistrationInterval = 15 * time.Second

// beat performs one registration POST and returns the HTTP status — with, on a
// refusal, whatever reason the server gave — or an error if the request could
// not be built or the round trip failed.
func (s *Server) beat(ctx context.Context, url string, body []byte, auth registrationAuth) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("content-type", "application/json")
	expiresAt, err := auth.authorize(ctx, req)
	if err != nil {
		return 0, "", err
	}
	// Never let the POST outlive the credential it carries. registrationTimeout
	// allows this request 10s, which is longer than a short-lived registration
	// token's entire life: without this bound a token minted with, say, 2s left
	// is presented to a host that answers in 3s, arrives expired, and comes back
	// as a 401 — indistinguishable at this layer from the id being owned by
	// another publisher, which is exactly what invalidate() would then report.
	// Bounded by the expiry instead, the same case surfaces as this credential's
	// own deadline, named below, and the next beat mints a fresh token.
	expired := func() bool { return false }
	if !expiresAt.IsZero() {
		deadlined, cancel := context.WithDeadline(ctx, expiresAt)
		defer cancel()
		req = req.WithContext(deadlined)
		// Only the credential's deadline, not a shutdown, which the heartbeat
		// recognises by the parent context and reports as no failure at all.
		expired = func() bool { return deadlined.Err() != nil && ctx.Err() == nil }
	}
	resp, err := registrationClient.Do(req)
	if err != nil {
		if expired() {
			return 0, "", fmt.Errorf("registration did not complete before the credential it presented expired at %s: %w (the issuer's token lifetime is shorter than this registration round trip)",
				expiresAt.UTC().Format(time.RFC3339), err)
		}
		return 0, "", err
	}
	defer drainAndClose(resp)
	return resp.StatusCode, refusalDetail(resp), nil
}

// refusalDetailMaxBytes bounds how much of a refusal body is read for the log.
// A host's reasons are a short JSON object; anything larger is not a reason.
const refusalDetailMaxBytes = 4 << 10

// refusalDetail extracts the reason a registration was refused, when the host
// gave one: the `reasons` list of an incompatible_runtime refusal, else its
// `error` code. Empty for an accepted registration or a bodiless refusal.
func refusalDetail(resp *http.Response) string {
	if resp.StatusCode < 400 {
		return ""
	}
	var refusal struct {
		Error   string   `json:"error"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, refusalDetailMaxBytes)).Decode(&refusal); err != nil {
		return ""
	}
	switch {
	case len(refusal.Reasons) > 0 && refusal.Error != "":
		return oneLine(refusal.Error + ": " + strings.Join(refusal.Reasons, "; "))
	case len(refusal.Reasons) > 0:
		return oneLine(strings.Join(refusal.Reasons, "; "))
	default:
		return oneLine(refusal.Error)
	}
}

// oneLine flattens the control characters out of text the host chose, so a
// reason carrying a newline cannot forge a log line of its own. The host is
// composition-local, but its reasons quote values this runtime never saw — a
// manifest field, an id another publisher registered — so what reaches the log
// is the host's text and never the host's framing.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// drainAndClose consumes what is left of a response body before closing it, so
// the connection returns to the pool instead of being dropped and re-dialled on
// the next beat. Bounded: a body larger than this is not worth reading to keep
// one connection.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// --- Module registration credentials ---
//
// The gateway federates a consumed module's /v1/<prefix>/* only against a
// signed, prefix-bound token issued by accounts — the shared cluster-internal
// token buys no per-caller binding and is refused. A backend obtains one by
// presenting the registration secret its composition provisioned for that
// prefix; the gateway brokers the exchange, because a composed module cannot
// reach accounts' internal listener itself.

const (
	moduleRegisterPath          = "/modules/_register"
	moduleRegistrationTokenPath = "/modules/_registration-token"
)

const (
	internalTokenHeader = "X-Codefly-Internal-Token"
	// moduleRegistrationHeader carries the signed, prefix-bound token
	// /modules/_register requires.
	moduleRegistrationHeader = "X-Codefly-Module-Registration"
	// moduleSecretHeader carries this backend's own registration secret on the
	// exchange that mints that token.
	moduleSecretHeader = "X-Codefly-Module-Secret"
)

// ModuleRegistrationSecretsEnvironmentVariable carries the registration secrets
// a composition provisioned into this backend, as comma-separated
// `prefix:secret` entries — the plaintext twin of the `prefix:sha256hex`
// digests the same composition declared to accounts. It is absent for a
// composition that federates nothing.
const ModuleRegistrationSecretsEnvironmentVariable = "CODEFLY__MODULE_REGISTRATION_SECRETS"

// moduleTokenRenewal is the most lead time the credential takes before an
// expiry, so a beat never presents a token that lapses between here and the
// gateway's check. It is a ceiling, not a requirement on the issuer: a token
// whose whole life is shorter is renewed at half its lifetime instead (see
// exchange). Conflating the two rejected every token the issuer chose to make
// short-lived — a 30s credential was refused outright, with a message blaming
// this host's clock.
const moduleTokenRenewal = 30 * time.Second

// moduleTokenMinimumLifetime is the least remaining validity an issued token
// must carry to be worth presenting at all. Below this the token would lapse
// mid-flight, so it is a boundary error rather than a credential.
const moduleTokenMinimumLifetime = 5 * time.Second

// registrationExchangeTimeout bounds one credential exchange — the module's and
// the solution's alike, which need the identical bound rather than one of them
// reaching into the other's constant. The registration beat is on a 15s cycle,
// so a stalled gateway must surface as a failed beat rather than wedge the beat
// loop for that module.
const registrationExchangeTimeout = 10 * time.Second

// registrationClient carries every registration request: the credential
// exchange and the three registration heartbeats. It is NOT http.DefaultClient.
//
// That transport carries Proxy: ProxyFromEnvironment, so with HTTP(S)_PROXY set
// and a NO_PROXY that does not cover the host's in-cluster names, these
// requests would be dialled to an arbitrary egress host — carrying, in headers,
// the module's plaintext registration secret, the cluster-internal token, and
// the signed token that decides where authenticated traffic for a prefix is
// forwarded. Every registration target is composition-local (each is resolved
// from the SDK's endpoint map), so none of them may be proxied. The issuing
// side of this same exchange refuses proxying for exactly this reason
// (module-saas-starter#527).
//
// It also refuses to follow redirects, for the same reason it refuses a proxy.
// net/http strips only Authorization, WWW-Authenticate and Cookie when a
// redirect crosses to another host; every other header — including the
// registration secrets and the cluster-internal token these requests carry in
// X-Codefly-* headers — is copied to the new target verbatim, and a 307/308
// re-sends the body with them. So anything able to answer at a registration URL
// with a Location (a gateway defect, an SSRF through it, a stale Service or DNS
// record claiming that name) would be handed the plaintext credential that this
// whole publisher binding exists to protect, and the theft would look like an
// ordinary successful beat. No registration endpoint has any reason to redirect,
// so a redirect is surfaced as the response it is and never followed.
//
// It also carries a Timeout. Without one, neither the heartbeat's context (which
// has no deadline) nor the transport bounds a gateway that accepts a
// registration and never answers: the beat blocks in Do forever, so that module
// — or, for the self-registrations, this whole solution — silently stops
// registering for the lifetime of the process, with no log and no recovery. The
// exchange bounds itself with registrationExchangeTimeout; this bounds the other
// three call sites the same way.
var registrationClient = &http.Client{
	Timeout:       registrationTimeout,
	Transport:     newRegistrationTransport(),
	CheckRedirect: refuseRedirect,
}

// refuseRedirect stops the client at the redirect itself: the 3xx is returned as
// the response, so the beat reports it like any other refusal instead of
// replaying this request's headers at whatever host the Location named.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// registrationTimeout bounds one registration request end to end. It matches
// registrationExchangeTimeout: a stalled gateway must surface as a failed beat,
// which the heartbeat then backs off, rather than wedge the loop.
const registrationTimeout = 10 * time.Second

func newRegistrationTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport
}

// parseModuleRegistrationSecrets decodes the comma-separated `prefix:secret`
// projection. An entry that is not a `prefix:secret` pair is dropped: the
// consequence — that module cannot register — is reported where it is
// actionable, by the missing-secret log in registerConsumedAPIs.
//
// Both halves are trimmed, matching how the registrar parses the digest twin of
// this same projection. Trimming only the entry left "documents : s3cret"
// keyed under "documents " with a leading space in the secret — a pair the
// registrar accepts and this side silently mangles into a lookup miss.
func parseModuleRegistrationSecrets(raw string) map[string]string {
	secrets := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		prefix, secret, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		prefix, secret = strings.TrimSpace(prefix), strings.TrimSpace(secret)
		if prefix == "" || secret == "" {
			continue
		}
		secrets[prefix] = secret
	}
	return secrets
}

// registrationAuth stamps the credential one registration POST presents, and
// drops it when the server refuses it. The host and gateway self-registrations
// present a short-lived token bound to this solution's publisher; a module
// registration presents one bound to the single prefix it may claim. Neither
// presents the shared cluster-internal token: it attests to no publisher and
// both surfaces refuse it (module-saas-starter#540).
type registrationAuth interface {
	// authorize stamps the credential on req and reports when that credential
	// stops being valid, or the zero time when it cannot expire mid-request.
	// The caller bounds the request by that instant: a credential that lapses
	// while the POST is still in flight is refused on arrival, and a refusal is
	// the one answer that cannot be told apart from the causes invalidate()
	// names, so it must surface as this credential's own deadline instead.
	authorize(ctx context.Context, req *http.Request) (expiresAt time.Time, err error)
	invalidate()
	// succeeded reports that the registration this credential authorized was
	// accepted. It closes a refusal episode, so the next refusal is judged on
	// its own rather than against a retry an earlier one already spent.
	succeeded()
}

// moduleCredential exchanges one consumed module's registration secret for the
// short-lived token /modules/_register requires, and holds it until renewal.
// Each instance is owned by exactly one registration beat, so its cached token
// needs no locking.
type moduleCredential struct {
	tokenURL      string
	internalToken string
	prefix        string
	secret        string

	token string
	// expiresAt is when token stops being honoured — not when it is renewed.
	// The registration POST is bounded by it, because a token that lapses
	// in flight is refused on arrival for a reason no refusal can express.
	expiresAt time.Time
	// renewAt is when the exchange must run again. Zero means "no usable
	// credential": either none has been obtained yet, or one was dropped.
	renewAt time.Time
	// mintedThisBeat records that token was obtained during the beat now in
	// flight, so a refusal of it cannot be blamed on staleness.
	mintedThisBeat bool
	// retriedAfterRefusal records that a refusal has already been answered with
	// a fresh mint, and that mint has not yet been superseded by a natural
	// renewal. It caps a refusal at one re-mint.
	retriedAfterRefusal bool
	warnedFreshRefusal  bool
	warnedShortLifetime bool
}

func (c *moduleCredential) authorize(ctx context.Context, req *http.Request) (time.Time, error) {
	c.mintedThisBeat = false
	// A zero renewAt means no credential yet, or one just dropped, so the
	// exchange runs. It cannot mean a cached-but-unusable token: exchange
	// refuses any expiry this process could not act on.
	if !time.Now().Before(c.renewAt) {
		// Renewing a token still held is a fresh episode: whatever refusal the
		// last re-mint was answering is over, so the next one earns its own retry.
		natural := c.token != ""
		token, expiresAt, renewAt, err := c.exchange(ctx)
		if err != nil {
			return time.Time{}, err
		}
		if natural {
			c.retriedAfterRefusal = false
		}
		c.token, c.expiresAt, c.renewAt, c.mintedThisBeat = token, expiresAt, renewAt, true
	}
	req.Header.Set(moduleRegistrationHeader, c.token)
	return c.expiresAt, nil
}

// invalidate drops the cached token so the next beat obtains a fresh one — but
// only when a fresh one could plausibly help.
//
// A registration can be refused for reasons a new token cannot repair: a gateway
// that does not trust the issuer, a prefix this module may not claim, skew on the
// gateway's clock, a perimeter check rejecting the request before the token is
// ever examined. Dropping unconditionally turned every one of those into a mint
// on every beat — an audited security event on the issuer, four times a minute
// per module, indefinitely, and silent after the first log line because the
// status never changes. Staleness is the one cause re-minting fixes, so a
// refusal buys exactly one re-mint: a token minted for this very beat is not
// stale, and neither is the replacement a previous refusal already bought.
func (c *moduleCredential) invalidate() {
	if c.mintedThisBeat || c.retriedAfterRefusal {
		if c.mintedThisBeat && !c.warnedFreshRefusal {
			c.warnedFreshRefusal = true
			// This is the signature of a cause outside the credential, so name
			// it: an operator reading "rejected (status 401)" alone would go
			// looking at provisioning, which is the one thing already proven
			// fine — the exchange that minted this token accepted the secret.
			log.Printf("registration for %q was refused while presenting a token minted for that same beat: the credential is not stale, so re-minting cannot fix it — check that the gateway trusts the issuer that signed it, that %q may be claimed by this module, and whether %s admits %s at all",
				c.prefix, c.prefix, moduleRegisterPath, internalTokenHeader)
		}
		return
	}
	// Spend the retry only when a drop actually follows, so the next beat's
	// fresh mint is the one attempt this refusal was owed.
	c.retriedAfterRefusal = true
	c.token, c.renewAt = "", time.Time{}
}

// succeeded ends the refusal episode: a registration this credential authorized
// was accepted, so a later refusal is a new fault — a second key rotation, say —
// and earns its own re-mint rather than inheriting the spent budget of the first.
func (c *moduleCredential) succeeded() {
	c.retriedAfterRefusal = false
}

// exchange runs the credential exchange against the gateway. It presents both
// the module secret, which identifies this module to accounts, and the
// cluster-internal token, which the gateway's own perimeter check requires.
//
// It returns the token, when it expires, and when to renew it. Expiry and
// renewal are separate answers: renewal is early by a lead, while expiry is the
// instant the gateway stops honouring the token, which is what a registration
// POST must not outlive.
func (c *moduleCredential) exchange(ctx context.Context) (string, time.Time, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, registrationExchangeTimeout)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"prefix": c.prefix})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	req.Header.Set("content-type", "application/json")
	// Absent rather than present-and-empty when unconfigured: an empty header
	// is the harder shape to diagnose at the gateway, which sees a caller
	// claiming a credential it does not have.
	if c.internalToken != "" {
		req.Header.Set(internalTokenHeader, c.internalToken)
	}
	req.Header.Set(moduleSecretHeader, c.secret)

	resp, err := registrationClient.Do(req)
	if err != nil {
		return "", time.Time{}, time.Time{}, err
	}
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, time.Time{}, fmt.Errorf("registration token exchange for %q rejected (status %d)", c.prefix, resp.StatusCode)
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return "", time.Time{}, time.Time{}, fmt.Errorf("registration token exchange for %q returned invalid json: %w", c.prefix, err)
	}
	if issued.Token == "" {
		return "", time.Time{}, time.Time{}, fmt.Errorf("registration token exchange for %q returned no token", c.prefix)
	}
	// An expiry this process cannot use is a boundary error, not a token to
	// cache: treated as "already expired" it would look like success while
	// re-running the exchange on every beat. The two unusable shapes have
	// different causes and different fixes, so they get different messages —
	// the old single message blamed the clock for a response that never carried
	// an expiry at all.
	now := time.Now()
	lifetime := issued.ExpiresAt.Sub(now)
	switch {
	case issued.ExpiresAt.IsZero():
		return "", time.Time{}, time.Time{}, fmt.Errorf(
			"registration token exchange for %q returned no expiry: the issuer omitted expiresAt, or spelled it differently (protobuf JSON spells it expires_at, which does not decode into this field)",
			c.prefix)
	case lifetime < moduleTokenMinimumLifetime:
		return "", time.Time{}, time.Time{}, fmt.Errorf(
			"registration token exchange for %q returned the expiry %s, already past or less than %s away (check this host's clock against the issuer's)",
			c.prefix, issued.ExpiresAt.UTC().Format(time.RFC3339), moduleTokenMinimumLifetime)
	}
	// Renew ahead of expiry, but never by more than half the credential's own
	// life: a lead longer than the lifetime would reject the token outright, and
	// the issuer's chosen lifetime is not this process's to veto.
	lead := moduleTokenRenewal
	if half := lifetime / 2; half < lead {
		lead = half
		if !c.warnedShortLifetime {
			c.warnedShortLifetime = true
			// Honoured, but say so once: at this lifetime the token cannot be
			// held across many beats, so the mint rate is the issuer's setting
			// and not a defect here.
			log.Printf("registration token for %q is issued with a %s lifetime, shorter than the %s renewal lead: it will be re-obtained roughly every %s",
				c.prefix, lifetime.Round(time.Second), moduleTokenRenewal, lead.Round(time.Second))
		}
	}
	return issued.Token, issued.ExpiresAt, issued.ExpiresAt.Add(-lead), nil
}

// --- Solution registration credentials ---
//
// The host binds a solution's registration to its publisher: the frontend
// accepts a manifest, and the gateway an upstream, only against a signed,
// solution-bound token that accounts mints to a caller presenting the
// registration secret the composition declared for that id. The shared
// cluster-internal token attests to no publisher and is refused on both
// (module-saas-starter#540). A token is minted per attempt and burned on use by
// each surface, so unlike the module credential there is nothing to cache: the
// exchange runs before every beat.

const (
	solutionRegisterPath          = "/solutions/_register"
	solutionRegistrationTokenPath = "/solutions/_registration-token"
)

const (
	// solutionRegistrationHeader carries the signed, solution-bound token both
	// /solutions/_register and /api/solutions/register require.
	solutionRegistrationHeader = "X-Codefly-Solution-Registration"
	// solutionSecretHeader carries this solution's own registration secret on
	// the exchange that mints that token.
	solutionSecretHeader = "X-Codefly-Solution-Secret"
)

// SolutionRegistrationSecretEnvironmentVariable carries the registration
// secret a composition provisioned for this solution — the plaintext twin of
// the `<id>:sha256hex` digest the same composition declared to the host in its
// `SOLUTION_REGISTRATION_SECRETS`. It is an explicit override; the workspace
// secret below is the declared path.
const SolutionRegistrationSecretEnvironmentVariable = "CODEFLY__SOLUTION_REGISTRATION_SECRET"

// SolutionRegistrationSecretGroup and SolutionRegistrationSecretKey name the
// workspace secret the runtime resolves through the SDK when no override is
// set: a composition declares the `solution-registration` group as a
// workspace-configuration dependency of the solution's backend and provisions
// `SECRET` in it (`codefly config generate solution-registration SECRET`
// locally; the cell's secret store when deployed).
const (
	SolutionRegistrationSecretGroup = "solution-registration"
	SolutionRegistrationSecretKey   = "SECRET"
)

// solutionTokenMinimumLifetime is the least remaining validity a minted
// registration token must carry to be worth presenting. This credential is
// presented on the very next round trip rather than held between beats, so the
// floor bounds one request: whatever lifetime the issuer chose, a token that
// outlives the registration POST is usable and must not be refused here.
//
// moduleTokenMinimumLifetime is 5s because that token *is* cached across beats,
// and copying the figure over rejected every genuinely single-use credential an
// issuer might mint — a 3s token failed every beat forever, with a message
// blaming this host's clock. The two floors bound different things, so they are
// deliberately different values.
const solutionTokenMinimumLifetime = time.Second

// solutionMintReportEvery is how many mints pass between one line reporting the
// running count. Minting one token per beat per surface is the contract's
// consequence and not a defect, but it is an audited event on the issuer, and
// the only place its rate could be observed was the issuer's own audit trail.
// If the burn-per-surface premise this design rests on ever stops holding, this
// is the number that says what abandoning the cache is costing.
const solutionMintReportEvery = 100

// solutionCredential mints this solution's registration token and presents it
// on one registration beat. Each self-registration heartbeat owns one, so it
// needs no locking.
type solutionCredential struct {
	tokenURL      string
	internalToken string
	id            string
	secret        string

	// refused records that the host refused the token the beat now in flight
	// presented. Nothing here is cached, so a refusal can never be staleness;
	// the flag only bounds the diagnostic to one line per refusal episode.
	refused bool
	// minted counts the tokens this credential has obtained, so the cost of
	// minting one per beat is visible here and not only on the issuer.
	minted int
}

func (c *solutionCredential) authorize(ctx context.Context, req *http.Request) (time.Time, error) {
	token, expiresAt, err := c.exchange(ctx)
	if err != nil {
		return time.Time{}, err
	}
	req.Header.Set(solutionRegistrationHeader, token)
	return expiresAt, nil
}

// invalidate is what a refusal calls. There is no cached token to drop — every
// beat presents one minted for it — so the refusal cannot be about staleness,
// and the only useful thing to do is say so, once: the exchange that minted the
// refused token already proved the secret, and the beat is bounded by the
// token's own expiry so it cannot have lapsed in flight either, which leaves
// the host's side of the credential (an id another publisher owns, a manifest
// the host finds incompatible, a gateway that does not trust the issuer).
func (c *solutionCredential) invalidate() {
	if c.refused {
		return
	}
	c.refused = true
	log.Printf("registration for solution %q was refused while presenting a token minted for that same beat: the exchange accepted this solution's secret, so provisioning is not the cause — check that %q is not registered by another publisher and that the host trusts the issuer that signed the token",
		c.id, c.id)
}

func (c *solutionCredential) succeeded() {
	c.refused = false
}

// exchange runs the credential exchange against the gateway. It presents both
// the solution secret, which identifies this solution to accounts, and the
// cluster-internal token, which the gateway's own perimeter check requires.
func (c *solutionCredential) exchange(ctx context.Context) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, registrationExchangeTimeout)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"id": c.id})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("content-type", "application/json")
	if c.internalToken != "" {
		req.Header.Set(internalTokenHeader, c.internalToken)
	}
	req.Header.Set(solutionSecretHeader, c.secret)

	resp, err := registrationClient.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer drainAndClose(resp)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// An unrouted path: a host from before the publisher-bound contract
		// (module-saas-starter < v0.0.61, not supported), or a wrong URL. There
		// is no other credential to fall back to — the shared cluster-internal
		// token proves no publisher — so the beat fails and names the route.
		return "", time.Time{}, fmt.Errorf("the solution registration exchange at %s answered 404: this host does not serve publisher-bound registration (module-saas-starter < v0.0.61 is not supported) or the URL is wrong (%s, or the %s it is derived from)",
			c.tokenURL, "GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL", "GATEWAY_REGISTER_URL")
	default:
		// accounts answers an undeclared id and a wrong secret identically, and
		// the gateway relays that; naming both here is what the reader needs.
		return "", time.Time{}, fmt.Errorf("registration token exchange for solution %q rejected (status %d): the host declares no %s entry for this id, or the provisioned secret does not match its digest",
			c.id, resp.StatusCode, "SOLUTION_REGISTRATION_SECRETS")
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return "", time.Time{}, fmt.Errorf("registration token exchange for solution %q returned invalid json: %w", c.id, err)
	}
	if issued.Token == "" {
		return "", time.Time{}, fmt.Errorf("registration token exchange for solution %q returned no token", c.id)
	}
	// The token is presented once, right now: an expiry that is absent or
	// already too close is a boundary error, not a credential.
	switch lifetime := time.Until(issued.ExpiresAt); {
	case issued.ExpiresAt.IsZero():
		return "", time.Time{}, fmt.Errorf("registration token exchange for solution %q returned no expiry: the issuer omitted expiresAt, or spelled it differently", c.id)
	case lifetime < solutionTokenMinimumLifetime:
		return "", time.Time{}, fmt.Errorf("registration token exchange for solution %q returned the expiry %s, already past or less than %s away (check this host's clock against the issuer's)",
			c.id, issued.ExpiresAt.UTC().Format(time.RFC3339), solutionTokenMinimumLifetime)
	}
	if c.minted++; c.minted%solutionMintReportEvery == 0 {
		// Per credential, not per solution: each self-registration surface has
		// its own, so the solution's actual mint rate is this figure times the
		// number of surfaces. Saying so matters — read as a whole-solution
		// total it understates the audited-event rate it exists to expose.
		log.Printf("solution %q: %d registration tokens minted on this credential alone (one self-registration surface, one mint per beat) — each an audited mint on the issuer. The host burns a token per surface, so none can be cached; this is what that costs",
			c.id, c.minted)
	}
	return issued.Token, issued.ExpiresAt, nil
}

// Gateway is a client bound to the caller's bearer. It exposes an HTTP client
// that forwards that bearer and the gateway base URL, so a solution can drive
// its own generated SDK against the gateway — every call stays authenticated
// and routed through the gateway.
//
// A module that authenticates by signed Work Context refuses a bearer alone;
// ForModule derives a gateway that carries both.
type Gateway struct {
	baseURL string
	bearer  string
	// orgID is the viewer's organization, which the bearer alone does not
	// carry. A Work Context is minted inside exactly one org.
	orgID string
	// delegation is the ask this gateway acts under, nil on the one a handler
	// is given. It holds the ask rather than a capability: see delegation.
	delegation *delegation
	contexts   *workContextCache
}

func newGateway(baseURL, bearer, orgID string) *Gateway {
	return &Gateway{
		baseURL:  baseURL,
		bearer:   bearer,
		orgID:    orgID,
		contexts: newWorkContextCache(),
	}
}

func (g *Gateway) BaseURL() string { return g.baseURL }

// HTTPClient returns an http.Client that injects the caller's bearer — and, on
// a gateway derived by ForModule, the viewer's Work Context — on every request.
// Satisfies connect.HTTPClient. Advanced escape hatch — prefer Unary.
func (g *Gateway) HTTPClient() *http.Client {
	transport := bearerTransport{bearer: g.bearer, base: gatewayTransport}
	if g.delegation != nil {
		transport.acting = g
	}
	return &http.Client{Transport: transport}
}

// bearerClient carries the viewer's bearer and nothing else. The mint runs on
// it rather than on HTTPClient: a capability minted for one module would
// otherwise ride along on the request that mints another's, and the edge
// verifies every presented context, so once the first lapsed it would 401 the
// very call meant to replace it.
func (g *Gateway) bearerClient() *http.Client {
	return &http.Client{Transport: bearerTransport{bearer: g.bearer, base: gatewayTransport}}
}

// gatewayTransport carries every request a solution makes through the gateway:
// the module reads a handler issues, and the mint that authenticates them. It
// is NOT http.DefaultTransport.
//
// That transport carries Proxy: ProxyFromEnvironment, so with HTTP(S)_PROXY set
// and a NO_PROXY that does not cover the host's in-cluster names, these requests
// would be dialled to an arbitrary egress host — carrying, in headers, the
// viewer's bearer and the signed capability minted on their behalf. The gateway
// is composition-local (its address is resolved from the SDK's endpoint map),
// exactly like every registration target, so none of this may be proxied
// either. It shares the registration transport's constructor because it needs
// the identical thing: the default transport with proxying dropped.
var gatewayTransport = newRegistrationTransport()

// --- Work Context ---
//
// The platform's module-facing auth model is not the bearer: a module derives
// tenant and subject from a signed capability naming it as the audience, and
// answers Unauthenticated to a bearer alone. The gateway only verifies and
// forwards a context that is already presented — nobody mints one for the
// viewer — so a solution reading a composed module has to mint it here.

// workContextStartTaskProcedure is the accounts RPC that mints a Task Work
// Context. The gateway routes it like any other Connect procedure, so it is
// reached on the same base URL the solution's module calls already use.
const workContextStartTaskProcedure = "/saas.accounts.v1.WorkContextService/StartTask"

// orgHeader carries the viewer's organization. The gateway injects it after it
// authenticates the bearer, replacing anything the caller sent.
const orgHeader = "x-org-id"

// workContextMintTimeout bounds one mint, so a stalled gateway surfaces as a
// failed handler rather than holding the viewer's request open indefinitely.
const workContextMintTimeout = 10 * time.Second

// workContextRenewal is the most lead time the cache takes before a capability
// expires, so a request never presents one that lapses between here and the
// edge's check. It is a ceiling, not a requirement on the issuer: a capability
// whose whole life is shorter is reused until half its lifetime is gone (see
// mint). Conflating the two would make every short-lived capability uncacheable
// and turn the cache into a mint per read, silently.
const workContextRenewal = 10 * time.Second

// workContextMinimumLifetime is the least remaining validity a minted
// capability must carry to be worth presenting at all. Below this it would
// lapse mid-flight, so it is a boundary error rather than a credential.
const workContextMinimumLifetime = 5 * time.Second

// warnedShortWorkContextLifetime carries the one-time notice that this issuer
// mints capabilities too short-lived to hold across a request. It is
// process-wide rather than per-request because that is a property of the
// issuer's configuration, not of any one viewer's call.
var warnedShortWorkContextLifetime sync.Once

// Scope is one slice of authority requested for a Work Context: what the module
// may be asked to do, on which resources, on the viewer's behalf. Empty
// ResourceIDs grants the actions across the whole ResourceKind.
type Scope struct {
	ResourceKind string
	Actions      []string
	ResourceIDs  []string
}

// workContextScope is saas.accounts.v1.WorkContextScope on the wire. Scope is
// this package's own type and carries no tags, so the accounts field spellings
// live here: a rename over there is a change to this file rather than to a
// public API this package's consumers can see.
type workContextScope struct {
	ResourceKind string   `json:"resourceKind"`
	Actions      []string `json:"actions,omitempty"`
	ResourceIDs  []string `json:"resourceIds,omitempty"`
}

func workContextScopes(scopes []Scope) []workContextScope {
	wire := make([]workContextScope, len(scopes))
	for i, scope := range scopes {
		wire[i] = workContextScope{
			ResourceKind: scope.ResourceKind,
			Actions:      scope.Actions,
			ResourceIDs:  scope.ResourceIDs,
		}
	}
	return wire
}

// ForModule returns a Gateway that acts for the viewer against one composed
// module. It mints a Task Work Context owned and actored by the viewer — the
// bearer is forwarded, so accounts resolves the same subject the module would
// have seen — naming audience and carrying no more authority than scopes, and
// presents it alongside the bearer on every request the returned gateway makes.
//
// audience is the module's facade entry-point: the `as` of its api.consumes
// target, which is both what the gateway routes /v1/<as>/* to and what the
// module verifies as its own audience. A solution declares the consumption
// once and names it here.
//
// One ask mints once, however many gateways are derived for it and from however
// many goroutines: the capability is cached per (org, audience, scopes) and
// shared with every gateway derived from the one the handler was given, and
// concurrent asks for it wait on the one mint in flight. Minting is an audited
// event on accounts, not a free call.
//
// The returned gateway holds the ask, not the capability — it resolves one per
// request — so a handler may keep it for as long as it keeps the viewer's
// request. Minting here as well means an ask accounts refuses fails at this
// call rather than inside some later round trip.
func (g *Gateway) ForModule(ctx context.Context, audience string, scopes ...Scope) (*Gateway, error) {
	if g.orgID == "" {
		// The gateway injects orgHeader from the caller's active org, so it is
		// present but empty for a viewer with no organization selected and for
		// an org-less API key. Naming only the absent case would send whoever
		// reads this to inspect a header the gateway demonstrably did set.
		return nil, fmt.Errorf(
			"cannot mint a work context for %q: no viewer organization (%s is absent or empty — the gateway injects it from the caller's active org, which is empty for a viewer with no organization selected or an org-less API key)",
			audience, orgHeader)
	}
	ask := startTaskRequest{OrgID: g.orgID, Audience: audience, AuthorityScopes: workContextScopes(scopes)}
	// The ask is the cache identity. The task and session ids name one mint
	// rather than what was asked for, so they are filled in per mint, below.
	key, err := json.Marshal(ask)
	if err != nil {
		return nil, err
	}
	acting := *g
	acting.delegation = &delegation{key: string(key), ask: ask}
	if _, err := acting.workContext(ctx); err != nil {
		return nil, err
	}
	return &acting, nil
}

// delegation is the ask a derived gateway acts under. It holds the ask and not
// the capability so that every request resolves a live one: a capability
// snapshotted when the gateway was derived lapses while the handler still holds
// it, and the edge verifies freshness on any presented context before routing,
// so the call would 401 there rather than reach the module at all — worse than
// the bearer-only gateway this replaced.
type delegation struct {
	key string
	ask startTaskRequest
}

// workContext resolves the capability this gateway acts under, minting one if
// the cache holds none that will outlive the call.
func (g *Gateway) workContext(ctx context.Context) (codefly.WorkContextToken, error) {
	return g.contexts.resolve(ctx, g.delegation.key, func(ctx context.Context) (codefly.WorkContextToken, time.Time, error) {
		ask := g.delegation.ask
		ask.TaskID, ask.SessionID = uuid.NewString(), uuid.NewString()
		return g.mint(ctx, ask)
	})
}

// startTaskRequest is saas.accounts.v1.StartTaskWorkContextRequest on the wire.
// The runtime speaks it as Connect JSON rather than linking the accounts client:
// a solution's host is not this package's dependency. Leaving actorPrincipalId
// unset is what makes the viewer both owner and actor of the Task.
type startTaskRequest struct {
	OrgID           string             `json:"orgId"`
	TaskID          string             `json:"taskId"`
	SessionID       string             `json:"sessionId"`
	Audience        string             `json:"audience"`
	AuthorityScopes []workContextScope `json:"authorityScopes"`
}

func (g *Gateway) mint(ctx context.Context, ask startTaskRequest) (codefly.WorkContextToken, time.Time, error) {
	body, err := json.Marshal(ask)
	if err != nil {
		return codefly.WorkContextToken{}, time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, workContextMintTimeout)
	defer cancel()
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+workContextStartTaskProcedure, bytes.NewReader(body))
	if err != nil {
		return codefly.WorkContextToken{}, time.Time{}, err
	}
	post.Header.Set("content-type", "application/json")
	resp, err := g.bearerClient().Do(post)
	if err != nil {
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q: %w", ask.Audience, err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		// Connect reports a refusal as a code and message under a mapped HTTP
		// status. Carry it through: an authority the viewer does not hold reads
		// nothing like a gateway that never routed the mint, and the status
		// alone cannot tell them apart.
		var refusal struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&refusal)
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q rejected (status %d, %q): %s",
			ask.Audience, resp.StatusCode, refusal.Code, refusal.Message)
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q returned invalid json: %w", ask.Audience, err)
	}
	token, err := codefly.ParseWorkContextToken(issued.Token)
	if err != nil {
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q returned an unusable token: %w", ask.Audience, err)
	}
	// An expiry this process cannot use is a boundary error, not a capability to
	// cache. Treated as "already lapsed" it would look like success while
	// re-running an audited mint on every single read — correct answers, no
	// error, no log. The two unusable shapes have different causes and different
	// fixes, so they get different messages.
	now := time.Now()
	lifetime := issued.ExpiresAt.Sub(now)
	switch {
	case issued.ExpiresAt.IsZero():
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf(
			"work context mint for %q returned no expiry: the issuer omitted expiresAt, or spelled it differently (protobuf JSON spells it expires_at, which does not decode into this field)",
			ask.Audience)
	case lifetime < workContextMinimumLifetime:
		return codefly.WorkContextToken{}, time.Time{}, fmt.Errorf(
			"work context mint for %q returned the expiry %s, already past or less than %s away (check this host's clock against the issuer's)",
			ask.Audience, issued.ExpiresAt.UTC().Format(time.RFC3339), workContextMinimumLifetime)
	}
	// Renew ahead of expiry, but never by more than half the capability's own
	// life: a lead longer than the lifetime would make every capability
	// uncacheable, and the issuer's chosen lifetime is not this process's to
	// veto.
	lead := workContextRenewal
	if half := lifetime / 2; half < lead {
		lead = half
		warnedShortWorkContextLifetime.Do(func() {
			// Honoured, but say so once: at this lifetime a capability cannot be
			// held across a whole request, so the mint rate is the issuer's
			// setting and not a defect here.
			log.Printf("work contexts are issued with a %s lifetime, shorter than the %s renewal lead: one will be re-minted roughly every %s",
				lifetime.Round(time.Second), workContextRenewal, lead.Round(time.Second))
		})
	}
	return token, issued.ExpiresAt.Add(-lead), nil
}

// workContextCache holds the capabilities minted while serving one request. The
// gateway a handler receives owns it and every gateway derived from that one
// shares it, so the cache lives exactly as long as the viewer's request.
type workContextCache struct {
	mu     sync.Mutex
	minted map[string]issuedWorkContext
	// minting holds the mint in flight for an ask, so concurrent asks for the
	// same one wait on it instead of each running their own. A handler that
	// fans out would otherwise spend one audited mint per goroutine for a
	// capability they all share.
	minting map[string]*pendingMint
}

func newWorkContextCache() *workContextCache {
	return &workContextCache{
		minted:  map[string]issuedWorkContext{},
		minting: map[string]*pendingMint{},
	}
}

type issuedWorkContext struct {
	token codefly.WorkContextToken
	// reuseUntil is when this capability stops being worth presenting — its
	// expiry less the renewal lead mint already applied.
	reuseUntil time.Time
}

// pendingMint is one mint in flight. Its result fields are written before done
// is closed and read only after, so the close/receive pair orders them.
type pendingMint struct {
	done  chan struct{}
	token codefly.WorkContextToken
	err   error
}

// resolve returns the capability for one ask, running mint only when the cache
// holds none that will outlive the call and no other caller is already minting
// it.
func (c *workContextCache) resolve(
	ctx context.Context,
	key string,
	mint func(context.Context) (codefly.WorkContextToken, time.Time, error),
) (codefly.WorkContextToken, error) {
	c.mu.Lock()
	if issued, ok := c.minted[key]; ok && time.Now().Before(issued.reuseUntil) {
		c.mu.Unlock()
		return issued.token, nil
	}
	if inflight, ok := c.minting[key]; ok {
		c.mu.Unlock()
		select {
		case <-inflight.done:
			// The leader's outcome is this caller's outcome. Retrying its
			// failure here would turn one refusal into one mint per waiter.
			return inflight.token, inflight.err
		case <-ctx.Done():
			return codefly.WorkContextToken{}, ctx.Err()
		}
	}
	inflight := &pendingMint{done: make(chan struct{})}
	c.minting[key] = inflight
	c.mu.Unlock()

	token, reuseUntil, err := mint(ctx)
	inflight.token, inflight.err = token, err

	c.mu.Lock()
	delete(c.minting, key)
	if err == nil {
		c.minted[key] = issuedWorkContext{token: token, reuseUntil: reuseUntil}
	}
	c.mu.Unlock()
	close(inflight.done)
	return token, err
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
	// acting, when set, is the delegated gateway this transport presents a
	// capability for. It is resolved per round trip rather than captured here:
	// a capability captured once lapses while the handler still holds the
	// gateway, and the edge rejects a stale context before routing.
	acting *Gateway
	base   http.RoundTripper
}

func (t bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Set("authorization", t.bearer)
	if t.acting != nil {
		token, err := t.acting.workContext(r.Context())
		if err != nil {
			return nil, err
		}
		if err := codefly.AttachWorkContext(r, token); err != nil {
			return nil, err
		}
	}
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

// siblingURL swaps the trailing `replacing` of base for path. It is how a
// derived federation endpoint follows an explicitly overridden one: both
// endpoints of the registration exchange must address the same gateway.
//
// It replaces a suffix rather than rebuilding from scheme+host, because a
// gateway is not always mounted at the root. Rebuilding dropped everything
// between the host and the endpoint, so a gateway served under a path prefix
// (GATEWAY_URL=http://gateway:8080/gw) registered at /gw/modules/_register while
// exchanging at /modules/_registration-token — an absolute URL, so validate()
// passed it, and a 404 on every beat thereafter.
func siblingURL(base, replacing, path string) string {
	if u, err := url.Parse(base); err != nil || !u.IsAbs() || u.Host == "" {
		// Unparseable or relative: hand the value straight back so config
		// validation reports the one broken URL the operator actually set,
		// rather than a second one synthesized from it.
		return base
	}
	prefix, ok := strings.CutSuffix(base, replacing)
	if !ok {
		// The override does not end in the endpoint we know how to pair, so its
		// sibling is not derivable — a query string, a trailing slash, or a
		// wholly custom path. Returning "" makes validate() refuse to boot and
		// name the module token URL, which is the one the operator must set
		// explicitly; synthesizing a plausible-looking guess would instead 404
		// on every beat.
		return ""
	}
	return prefix + path
}
