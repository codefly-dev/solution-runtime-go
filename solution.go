// Package solution is a generic runtime for "solution" modules — independently
// deployed extensions that plug into a host at runtime with no build-time
// coupling. It owns everything every solution needs identically: env/config, a
// plain-HTTP listener on the port Codefly resolves, CORS, static Module
// Federation asset serving, the capability handshake, the solution manifest,
// the published contract, the connection to the authority interface, the
// passthrough that relays a page's module calls as the viewer, and serving the
// solution's MCP server to agent clients. A solution author supplies a
// manifest and one or more handlers; each handler receives a Gateway bound to
// the person the authority says the request is for.
//
// # The runtime runs under the authority interface
//
// A solution is reached through the authority's edge (codefly-dev/authority:
// the authority gateway on a laptop, the host in a cell), which signs the
// person in and sends each request on with the person's Work Context addressed
// to this module. This runtime holds no session bearer and mints nothing: it
// asks the authority's Check who that context is for and whether it holds the
// route, and every Work Context it acts under is issued by the authority — a
// child of the edge's context through one of this module's declared bindings
// (ForParent), or this module's own through a binding (ForBinding). A
// composition names the authority in workspace configuration
// authority/endpoint, and a boot without one is refused.
//
// The saas host this runtime used to run against — a bearer forwarded to a
// gateway, a Task Work Context minted through accounts for the viewer, an
// execution credential obtained from the host's module broker, the install
// step, and the MCP identity the gateway stamped in headers — is deleted, not
// fenced. Nothing bridges the two models.
//
// # A runtime does not register itself
//
// Presence is delivered: a signed presence document declares which solution
// runs on which host, and the host reconciles towards it. Health is answered,
// never pushed: the host probes the destination its own presence document
// names.
//
// This package knows nothing about any specific host or solution: what it
// depends on beyond the standard library is the Codefly SDK it resolves
// configuration through, Core, the authority client, Connect and gRPC for the
// wire, and the official MCP SDK.
package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// Manifest is the small, solution-specific description the author provides.
//
// What the host lists the solution under — its title, nav order, exposed
// module, host contract, dashboard and surfaces — is not declared here. It is
// declared once, in the file FrontendFileName names, which Frontend embeds and
// the CLI delivers in the presence document: two readers of one file cannot
// disagree, where a Go field beside a file could.
type Manifest struct {
	ID           string   // logical id / service alias, e.g. "widgets-go"
	Contract     string   // capability contract id (default: ID)
	Capabilities []string // capability feature ids
	// Frontend is the declared frontend file, FrontendFileName, embedded with
	// go:embed from beside the backend's service.codefly.yaml. Nil means a
	// headless component. A present file is validated even when empty, and
	// the manifest route serves only when a frontend is declared. Contract and Capabilities stay Go fields because the
	// capability handshake (/.well-known/capabilities) is the backend's own
	// and the frontend block does not carry them.
	Frontend []byte
	// Assets, when set, is what /assets/ serves: the built Module Federation
	// remote (mf-manifest.json at its root, and every chunk it names), usually
	// embedded in the binary with go:embed and narrowed with fs.Sub to the
	// build's output directory. A solution that ships its frontend this way
	// reads nothing from disk to serve it, so it runs with a read-only root
	// filesystem and cannot drift from the binary it was built with.
	//
	// When nil, /assets/ serves the ASSETS_DIR directory, as before.
	Assets fs.FS
}

// validateID refuses an empty id. It is what the host's presence document
// names this solution by, the audience a Work Context the edge sends is
// addressed to, the route the edge forwards (/v1/<id>), what the published
// contract carries as `Solution`, and what every refusal in this package
// identifies the process as — so an empty one makes a misconfigured
// deployment anonymous in its own logs and unreachable through the edge.
func (m Manifest) validateID() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("this solution declares no id: Manifest.ID is what the host's presence document names it by, the audience the authority addresses its Work Contexts to, what the published contract reports as its own, and what every refusal here identifies this process as. Set it to the module id the composition deploys")
	}
	return nil
}

// Handler is a solution endpoint. It receives a Gateway bound to the viewer
// and returns any JSON-serializable value. ClientError, GatewayError and
// Connect errors retain actionable statuses; untyped errors return 502.
type Handler func(ctx context.Context, gw *Gateway) (any, error)

// RequestHandler receives the incoming request and the same viewer-bound
// Gateway as Handler. Implementations must bound and validate request bodies
// before use. Return a ClientError to reject invalid input with a 4xx status.
// GatewayError and Connect errors retain actionable statuses; untyped errors
// return 502.
type RequestHandler func(r *http.Request, gw *Gateway) (any, error)

// ClientError rejects a request with StatusCode (400–499) and a public Message.
// Handlers may wrap it with %w; only Message is sent to the caller, so wrapping
// context stays private. An invalid StatusCode is treated as a handler error
// and returns 502 instead. Both Handle and HandleRequest support ClientError.
type ClientError struct {
	StatusCode int
	Message    string
}

func (e *ClientError) Error() string { return e.Message }

// Server wires a manifest and handlers into a running solution.
type Server struct {
	manifest Manifest
	// frontend is the declared file decoded at boot (parseFrontend), which the
	// manifest route serves from.
	frontend frontendDeclaration
	handlers map[string]RequestHandler
	// consumed is the passthrough declaration (Consumes); passthrough is its
	// resolved routes, checked by Serve before it listens.
	consumed    []ConsumedModule
	passthrough map[string]passthroughRoute
	// relays is each relayed consumed module's binding and connection
	// (passthrough_authority.go).
	relays map[string]*moduleRelay
	// mcp is the MCP server the solution declared with ServeMCP, nil when it
	// declared none; mcpRedeclared records a second ServeMCP, which the boot
	// refuses rather than letting the last call quietly be the only surface.
	mcp           *mcpSurface
	mcpRedeclared bool
	cfg           config
	// host is the authority interface the composition names, dialled at boot.
	host *hostAuthority
	// declaredContract is the contract the author declared (Contract);
	// contract is that contract resolved for the profile this process runs
	// under, which is what it publishes.
	declaredContract ModuleContract
	contract         effectiveContract
	// boundListener is a listener this process was handed instead of binding
	// one itself. Nil in every deployment: the port comes from the SDK and
	// listen() binds it.
	//
	// It exists because a test harness cannot hand over a free *port* without
	// a race. Binding :0, reading the number and closing the socket leaves a
	// window in which anything else asking the OS for an ephemeral port can be
	// given the same one — and this suite stands up httptest servers
	// constantly, so it was given it, intermittently, in a different test each
	// time. Narrowing the window with a retry was the previous attempt and
	// could not close it. Handing over the listener removes the window
	// entirely, because nothing is ever released.
	boundListener net.Listener
}

type config struct {
	listenHost string
	port       string
	// authorityEndpoint is the authority interface the composition names
	// (authority/endpoint), which answers who every request is for and issues
	// every Work Context this process acts under (authority.go).
	authorityEndpoint string
	// routeAdvisory is hop/ENFORCEMENT=warn: the authority's route check is
	// asked as advice and its refusal logged rather than answered.
	routeAdvisory bool
	// dialled is every address this process talks to: the authority, and each
	// relayed module's hop once the relays are opened.
	//
	// It exists so nothing has to re-read the configuration to ask "is this
	// one of ours?" — which is both a deferred configuration read the
	// environment boundary refuses, and work repeated per error result. Its
	// one consumer is withoutRuntimeAddresses, the net that stops a tool
	// telling an MCP client an address this runtime dialled.
	dialled   []string
	assetsDir string
	// projectedTokenPath is the file the platform projects this workload's
	// credential into, which the authority takes as the actor of every issue.
	// It is re-read on every call, because the projection is rotated under the
	// running process and a token read once at boot stops verifying long
	// before the process stops running.
	projectedTokenPath string
	// transport is the composition's answer to whether a plaintext hop inside
	// the cell is carried by a mutually authenticated mesh, and whether this is
	// a local run — read once here and handed to the SDK's endpoint rule, which
	// is the one copy of the rule that admits a cleartext module address. See
	// meshTransport.
	transport meshTransport
	// profile is the configuration profile this process runs under, which the
	// published contract is keyed by. A deployed environment has a profile of
	// its own (codefly-dev/core#687, fixed in core v0.7.1), so a contract that
	// declares only "local" is refused in a deployment rather than read as if
	// the deployment were a developer machine.
	profile string
	// runtimeContext is the kind of runtime Codefly says this process runs in,
	// read from one explicit signal; it is what tells a native run's loopback
	// listener from a container's (nativeListener).
	runtimeContext string
	// environmentLoadErr is the failure, if any, of loading Codefly's injected
	// carriers. Every SDK-resolved value above is empty when that load failed,
	// so validate() must say so rather than report each empty value as
	// something the composition forgot to provision.
	environmentLoadErr error
	// consumerIdentityErr is Init's refusal to pin this process's module:
	// CODEFLY__MODULE unset, or naming a different module from the one the
	// process was first pinned to. The SDK resolves no endpoint without that
	// pin, so validate() refuses it whether or not anything below came from an
	// override.
	consumerIdentityErr error
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// listenPort is the port of this service's own endpoint address. Codefly hands a
// service its own endpoint as a bare "host:port" (a rendered cell writes
// "localhost:8080"), and other endpoints as URLs; url.Parse reads the bare form
// as scheme "localhost" with no port, which left every rendered solution
// refusing to boot with an empty listen port. Both forms resolve here.
func listenPort(self string) string {
	if strings.Contains(self, "://") {
		if u, err := url.Parse(self); err == nil {
			return u.Port()
		}
		return ""
	}
	if _, port, err := net.SplitHostPort(self); err == nil {
		return port
	}
	return ""
}

// listenHost preserves the owning endpoint's allocated interface on native runs.
func listenHost(self string) string {
	if strings.Contains(self, "://") {
		if u, err := url.Parse(self); err == nil {
			return u.Hostname()
		}
		return ""
	}
	host, _, err := net.SplitHostPort(self)
	if err != nil {
		return ""
	}
	return host
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

// loadConfig resolves every address, port, and path through the Codefly SDK so
// nothing is hardcoded: this process's own endpoint, the authority the
// composition names, the mesh assertion, and the projected credential's path.
//
// Nothing here resolves a credential value, and nothing here resolves an
// identity: the listener is plain HTTP, and the cell's mesh carries transport
// security and destination identity for every hop inside it.
func loadConfig(ctx context.Context, initErr error) config {
	// Init fails for one of two reasons, and they are fixed in different
	// places: the carriers did not load, or the process named no module (or a
	// different one from the module it was first pinned to). Only the first
	// means every SDK-resolved value below is suspect; the second is refused
	// outright, because the SDK resolves no endpoint for a consumer it cannot
	// identify and its contract is that such a process does not serve.
	environmentLoadErr, consumerIdentityErr := initErr, error(nil)
	if errors.Is(initErr, resources.ErrConsumerNotIdentified) || errors.Is(initErr, codefly.ErrAuthorityValueChanged) {
		environmentLoadErr, consumerIdentityErr = nil, initErr
	}

	// Own endpoint: the port Codefly assigned this service, not a fixed default.
	self := address(ctx, "", "", "http", "http")
	port := env("PORT", "")
	if port == "" && self != "" {
		port = listenPort(self)
	}

	// Whether a plaintext hop inside the cell is carried by the mesh, and
	// whether this is a local run: the two facts the SDK's endpoint rule
	// decides on. Read here, once, and answered from the snapshot wherever
	// the rule asks — the rule is called when each relay is opened, and a
	// configuration value is fixed at process start anyway.
	query := codefly.For(ctx)
	transport := meshTransport{local: query.IsLocalRun()}
	transport.value, transport.set, transport.err = query.WorkspaceValueIfSet(workcontext.MeshTransportGroup, workcontext.MeshTransportKey)

	authorityEndpoint, _ := query.WorkspaceConfiguration(AuthorityInterfaceGroup, AuthorityEndpointKey)
	enforcement, _ := query.WorkspaceConfiguration(EnforcementGroup, EnforcementKey)
	authorityEndpoint = strings.TrimSpace(authorityEndpoint)
	return config{
		port:               port,
		listenHost:         listenHost(self),
		authorityEndpoint:  authorityEndpoint,
		routeAdvisory:      strings.EqualFold(strings.TrimSpace(enforcement), "warn"),
		assetsDir:          env("ASSETS_DIR", "../fe-remote/dist"),
		dialled:            dialledAddresses(authorityEndpoint),
		projectedTokenPath: strings.TrimSpace(env(ProjectedTokenFileEnvironmentVariable, DefaultProjectedTokenFile)),
		transport:          transport,
		profile:            strings.TrimSpace(env(ContractProfileEnvironmentVariable, codefly.Environment())),
		runtimeContext:     strings.TrimSpace(env(resources.RuntimeContextPrefix, "")),
		// Carried here, which the refactor that changed this function's
		// signature dropped: the refusals and the boot log exist to tell an
		// operator "the SDK resolved nothing" apart from "loading the injected
		// environment failed first", and with this left unset they all read as
		// the former. Sending someone to inspect provisioning over a variable
		// they broke themselves is the specific mistake validate() was written
		// to stop making.
		environmentLoadErr:  environmentLoadErr,
		consumerIdentityErr: consumerIdentityErr,
	}
}

// meshTransport is the SDK's TransportSource answered from values read once at
// boot, in loadConfig, rather than from the SDK at the moment the rule asks.
//
// A snapshot is the right shape twice over. The value is a composition
// setting, fixed at process start like every other configuration value, so
// re-reading it answers the same thing. And every environment read in this
// package sits in loadConfig's call tree, where validate() governs the result
// — the rule is asked when each relay is opened, and a live accessor captured
// there would be a read after boot that nothing judges.
type meshTransport struct {
	// value, set and err are internal-transport/mesh-protected exactly as the
	// SDK answered it, so the SDK's own reading of the assertion (only the
	// literal "true" asserts; any other value is an error) is the one in force.
	value string
	set   bool
	err   error
	local bool
}

func (t meshTransport) WorkspaceValueIfSet(name, key string) (string, bool, error) {
	if name != workcontext.MeshTransportGroup || key != workcontext.MeshTransportKey {
		return "", false, fmt.Errorf("%s/%s is not a transport value this process read at boot", name, key)
	}
	return t.value, t.set, t.err
}

func (t meshTransport) IsLocalRun() bool { return t.local }

// ContractProfileEnvironmentVariable overrides the configuration profile the
// published contract is read under. Unset, it is the Codefly environment's own
// name, which is how Core resolves a profile for an environment that declares
// none (resources.Environment.ConfigurationProfileNames). A deployed
// environment therefore reads its own profile rather than the developer
// machine's — the gap codefly-dev/core#687 named and core v0.7.1 closed.
const ContractProfileEnvironmentVariable = "CODEFLY__CONTRACT_PROFILE"

// ProjectedTokenFileEnvironmentVariable overrides where this workload's
// projected credential is read from, for an operator with a projection the
// resolver cannot see. DefaultProjectedTokenFile is the CLI's projection, which
// every Codefly-managed deployment mounts; the file is a path this process
// reads on every call to the authority, never a value, because the projection
// is rotated under the running process.
const (
	ProjectedTokenFileEnvironmentVariable = "CODEFLY__WORKLOAD_TOKEN_FILE"
	DefaultProjectedTokenFile             = "/var/run/secrets/codefly/token"
)

// validate rejects a config the runtime cannot actually serve under. When
// neither the SDK nor an explicit env override resolves a value, loadConfig
// leaves it empty; without this check Serve would bind ":"+"" — which the kernel
// happily accepts as a random port — and would dial an authority at "". Both
// are the exact silent no-op this whole SDK resolution effort exists to
// eliminate, so an unresolved config must fail loud at boot rather than come up
// looking healthy on the wrong port.
//
// Every refusal names the value and the provisioning path that fixes it, and
// each cause is separated from the ones it looks like: "the SDK resolved
// nothing" is a different sentence from "loading the injected environment
// failed first", because one generic message sent an operator to inspect
// endpoint resolution over a variable they had broken themselves.
func (c config) validate() error {
	// Before any endpoint: with no consumer pinned, every one of them is empty
	// for that reason and not for the one its own refusal would name.
	if c.consumerIdentityErr != nil {
		return fmt.Errorf("the Codefly SDK could not identify the module this process belongs to: %w — %s names it, every Codefly-managed flow sets it, and the SDK resolves no endpoint for a process it has not pinned, so this one does not serve",
			c.consumerIdentityErr, resources.ModulePrefix)
	}
	if p, err := strconv.Atoi(c.port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("unresolved listen port %q: set PORT or ensure the SDK resolves this service's http endpoint", c.port)
	}
	// The authority answers who every request is for and issues every Work
	// Context this process acts under; without it no route can be served.
	if c.authorityEndpoint == "" {
		if c.environmentLoadErr != nil {
			return fmt.Errorf("no authority interface is configured, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
				c.environmentLoadErr)
		}
		return fmt.Errorf("no authority interface is configured: this runtime is reached through the authority's edge and asks the authority who each request is for, so it cannot serve without one — the composition names it in workspace configuration %s/%s (an ${endpoint:…} reference the run resolves)",
			AuthorityInterfaceGroup, AuthorityEndpointKey)
	}
	// The projected credential is what the authority takes as the actor of
	// every issue; a path nothing is projected at is named here, not when the
	// first issue is refused.
	if c.projectedTokenPath == "" {
		return fmt.Errorf("no projected workload credential path resolved: the authority takes this workload's projected credential as the actor of every Work Context it issues, so it is required. The platform projects it at %s; %s overrides the path",
			DefaultProjectedTokenFile, ProjectedTokenFileEnvironmentVariable)
	}
	if err := resources.ValidateConfigurationProfileName(c.profile); err != nil {
		return fmt.Errorf("unusable contract profile %q: %w — it is the Codefly environment's own name unless %s overrides it",
			c.profile, err, ContractProfileEnvironmentVariable)
	}
	if c.nativeListener() {
		ip := net.ParseIP(c.listenHost)
		if c.listenHost != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("native listener requires the SDK-resolved loopback host of this service's http endpoint; PORT overrides only its port")
		}
	}
	c.logResolved()
	return nil
}

// logResolved says once, at boot, what this process resolved.
func (c config) logResolved() {
	if c.environmentLoadErr != nil {
		// Everything above resolved, so the load failure cost nothing this boot
		// needs — but it is still the reason a later SDK read may come back
		// empty, and it has to be said once rather than inferred from the next
		// surprise.
		log.Printf("codefly: the injected environment did not load cleanly; every SDK-resolved value that is present came from an override: %v", c.environmentLoadErr)
	}
	// The endpoint is an address the run resolved, never a URL that could
	// carry a credential.
	log.Printf("codefly: the authority interface is at %q; every request's viewer and every Work Context this process acts under come from it", c.authorityEndpoint)
}

// New starts a solution builder for the given manifest.
func New(manifest Manifest) *Server {
	if manifest.Contract == "" {
		// The solution's own id, which is what the field's documentation has
		// always promised. It used to default to a product's name — a literal
		// from one deployment, in a runtime that is supposed to know nothing
		// about any specific solution, so every solution that left the field
		// unset announced that product's capability contract to the host.
		manifest.Contract = manifest.ID
	}
	s := &Server{manifest: manifest, handlers: make(map[string]RequestHandler)}
	return s
}

// Handle registers a solution endpoint. Chainable.
func (s *Server) Handle(path string, handler Handler) *Server {
	return s.HandleRequest(path, func(r *http.Request, gw *Gateway) (any, error) {
		return handler(r.Context(), gw)
	})
}

// HandleRequest registers an endpoint that consumes request input. It uses the
// same viewer check and CORS as Handle.
func (s *Server) HandleRequest(path string, handler RequestHandler) *Server {
	s.handlers[path] = handler
	return s
}

// Serve resolves this process's configuration, connects to the authority, and
// blocks serving the solution over plain HTTP on the port Codefly resolved —
// the cell's mesh carries the hop.
//
// It registers nothing. Presence and authority are delivered to the host; the
// only thing this runtime tells anyone about itself is what it answers when
// asked.
func (s *Server) Serve() error {
	ctx := context.Background()
	ln, err := s.start(ctx)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// start is the whole boot up to the listener: the declaration checks, the
// resolved configuration, the authority connection and the relays, the
// published contract, and the listener on the resolved port. Split from Serve
// so a test boots the real thing on an ephemeral port — every refusal below is
// a refusal of a real boot and not of a path only tests take.
func (s *Server) start(ctx context.Context) (net.Listener, error) {
	// Before anything the environment owns: a declaration the author got wrong
	// is wrong in every environment, and saying so first keeps that mistake
	// from reading as one more unresolved address.
	if err := s.manifest.validateID(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	if s.manifest.Frontend != nil {
		frontend, err := parseFrontend(s.manifest.Frontend)
		if err != nil {
			return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
		}
		s.frontend = frontend
	}
	if err := s.validateMCPDeclaration(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	// The SDK owns environment resolution, and since sdk-go v0.3.1 that begins
	// with Init: it loads Codefly's injected carriers so endpoint and
	// workspace-configuration lookups resolve from them (falling back to the
	// local native workspace map when not running under the runtime), and it
	// pins the module this process belongs to from CODEFLY__MODULE. The SDK
	// refuses every endpoint query before that pin, so a boot that only loaded
	// the carriers — which this one did — resolved no port and reported it as
	// something the composition forgot to provision. Kept, not swallowed:
	// loadConfig separates the two failures and validate() refuses each by its
	// own cause.
	_, initErr := codefly.Init(ctx)
	if initErr != nil {
		log.Printf("codefly: init: %v", initErr)
	}
	s.cfg = loadConfig(ctx, initErr)
	if err := s.cfg.validate(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	routes, err := resolvePassthrough(s.consumed)
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.passthrough = routes
	authority, err := dialAuthority(s.cfg.authorityEndpoint, s.cfg.projectedTokenPath, s.manifest.ID, s.cfg.routeAdvisory)
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.host = authority
	// The passthrough relays each consumed module, as the viewer, through the
	// hop and the binding the composition names for it.
	if s.relays, err = s.openRelays(codefly.For(ctx).WorkspaceConfiguration); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	// The contract this solution publishes is resolved from the same
	// declaration, under the profile this process runs in, and every value it
	// requires is named in the refusal when it is absent.
	contract, err := s.resolveContract()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.contract = contract
	ln, err := s.listen()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	return ln, nil
}

// serve wires the routes and serves on ln until ctx is cancelled. Split from
// Serve so a test can boot a real solution on an ephemeral listener and
// exercise the whole served surface.
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/solution.json", withCORS(s.handleManifest))
	mux.HandleFunc("/.well-known/capabilities", withCORS(s.handleCapabilities))
	mux.HandleFunc(ContractPath, withCORS(s.handleContract))
	// Health is answered, never pushed. The host probes the destination its own
	// presence document names; this process does not report its liveness
	// anywhere, and has no way to make itself present by answering.
	mux.HandleFunc(HealthPath, s.handleHealth)
	for path, handler := range s.handlers {
		mux.HandleFunc(path, withCORS(s.wrapRequest(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", withCORSHandler(s.assetsHandler())))
	if err := s.mountPassthrough(mux); err != nil {
		return err
	}
	if err := s.mountMCP(mux); err != nil {
		return err
	}

	srv := &http.Server{
		Handler: mux,
		// See inboundHeaderTimeout and inboundIdleTimeout: with both unset, a
		// peer that connects and never sends a request line holds a goroutine
		// and a descriptor for as long as it likes.
		ReadHeaderTimeout: inboundHeaderTimeout,
		IdleTimeout:       inboundIdleTimeout,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	log.Printf("solution %q listening on %s (authority=%s, profile=%s)", s.manifest.ID, ln.Addr(), s.cfg.authorityEndpoint, s.cfg.profile)
	if serveErr := srv.Serve(ln); !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}

	return nil
}

// nativeListener says whether this process binds the loopback host of its own
// resolved endpoint — a native local run — rather than every interface, as a
// container or a pod does under the platform's network admission.
func (c config) nativeListener() bool {
	return c.transport.local && c.runtimeContext != resources.RuntimeContextContainer && c.runtimeContext != resources.RuntimeContextKubernetes
}

// listen binds the resolved port, or serves on the listener a test handed over
// (see boundListener).
//
// Plain TCP. Inside the cell the mesh carries transport security and
// destination identity for every hop, and admits this port only from the
// edge's principal — so there is no certificate to present and no caller to
// verify here, and a listener that did either would be a second copy of a
// decision the cell makes for every workload. What this process still decides
// is what a caller may do once admitted, which the authority's Check of the
// Work Context each request carries governs route by route.
func (s *Server) listen() (net.Listener, error) {
	if s.boundListener != nil {
		return s.boundListener, nil
	}
	host := ""
	if s.cfg.nativeListener() {
		host = s.cfg.listenHost
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, s.cfg.port))
	if err != nil {
		return nil, fmt.Errorf("listen on :%s: %w", s.cfg.port, err)
	}
	return ln, nil
}

// inboundHeaderTimeout bounds how long a connection may take to deliver a
// request's headers, and inboundIdleTimeout how long a keep-alive connection
// may sit between requests. Neither bounds a whole request, because a declared
// long-running stream is conforming traffic.
const (
	inboundHeaderTimeout = 10 * time.Second
	inboundIdleTimeout   = 30 * time.Second
)

// handleHealth reports process health. It asks the authority nothing.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

// HealthPath is where this runtime answers a health probe. It is a plain 200 on
// the listener the presence document names, which is the whole of this
// runtime's part in being observed: the host decides whether this binding is
// healthy, and nothing this process says can make it present.
const HealthPath = "/health"

// solutionManifestSchemaMajor is the major of the manifest document this
// runtime serves. The host checks it before activating a remote and treats a
// silent manifest as 1, so this says out loud what silence would assert. The
// host contract major beside it is the author's to declare, in the frontend
// file: it is the page that is built against a host contract, not this runtime.
const solutionManifestSchemaMajor = 1

// assetsHandler serves the frontend build under /assets/ (the prefix already
// stripped): from Manifest.Assets when the solution ships one, else from the
// ASSETS_DIR directory. Both go through the standard file server, so content
// types and range/conditional handling are the same whichever source serves.
func (s *Server) assetsHandler() http.Handler {
	var files http.Handler
	if s.manifest.Assets != nil {
		files = http.FileServerFS(s.manifest.Assets)
	} else {
		files = http.FileServer(http.Dir(s.cfg.assetsDir))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		files.ServeHTTP(&assetCacheWriter{ResponseWriter: w, cacheControl: assetCacheControl(r.URL.Path)}, r)
	})
}

// assetCacheWriter stamps an asset's cache policy on the response, but only on
// one that delivers or confirms the asset. A 404 for a hashed chunk — asked of
// an old replica mid-rollout — must not be cached for a year under the name
// the new build will serve it at.
type assetCacheWriter struct {
	http.ResponseWriter
	cacheControl string
	wrote        bool
}

func (w *assetCacheWriter) WriteHeader(status int) {
	if !w.wrote {
		w.wrote = true
		policy := w.cacheControl
		if status >= 300 && status != http.StatusNotModified {
			policy = "no-cache"
		}
		w.Header().Set("cache-control", policy)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *assetCacheWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// contentHashedAsset matches a file name carrying a build content hash — a
// run of at least eight hex digits between separators, as the bundlers emit
// ("123.3f9a1c2b.js", "index-3f9a1c2b0d.css").
var contentHashedAsset = regexp.MustCompile(`[.-][0-9a-f]{8,}\.[A-Za-z0-9]+$`)

// assetCacheControl is the caching a served asset may have. A content-hashed
// file never changes under its name, so it is cached for good. Everything
// else — above all mf-manifest.json and the remote entry, whose names are
// fixed so the host can find them — must be revalidated on every load, or a
// browser keeps a manifest naming chunks the redeployed solution no longer
// serves.
func assetCacheControl(name string) string {
	if contentHashedAsset.MatchString(path.Base(name)) {
		return "public, max-age=31536000, immutable"
	}
	return "no-cache"
}

// federationManifestPath is where this runtime serves its Module Federation
// manifest, relative to its own backend: the /assets/ file server in serve.
const federationManifestPath = "/assets/mf-manifest.json"

// frontendManifestURL is the path this solution's Module Federation manifest is
// served at, relative to this backend's own origin. The host resolves it
// against the route by which it reaches this solution — a route this runtime
// does not know and must not encode.
//
// It is a path and nothing else. It used to be an absolute URL, built from a
// public URL or, with none set, from this process's own listen address: true
// in a browser on the developer's machine and in no other browser anywhere, so
// every deployed solution registered a manifest the product could not load.
// The origin a browser reaches this solution through is named by the route in
// the presence document, which is the host's to resolve.
func (s *Server) frontendManifestURL() string {
	return federationManifestPath
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	if s.manifest.Frontend == nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, s.manifestMap())
}

func (s *Server) handleCapabilities(w http.ResponseWriter, _ *http.Request) {
	// The same majors the manifest declares, from the same places: the schema
	// major from the one constant, the host contract from the declared file.
	// Typed here, a bump of either would leave this document announcing the
	// old major while the manifest announced the new one, and a host that
	// checks both would see one solution claiming two different contracts.
	writeJSON(w, http.StatusOK, map[string]any{
		"schemaVersion": solutionManifestSchemaMajor,
		"contract":      s.manifest.Contract,
		"contractMajor": s.frontend.HostContract,
		"capabilities":  s.manifest.Capabilities,
	})
}

// wrapRequest serves one handler route as the viewer. The edge sends the
// request on with the person's Work Context for this module — or a module
// calling it as a tool sends the child the authority issued it — and who it is
// for is the authority's Check of that context, which also applies this
// module's delivered policy for the route. No session bearer reaches this
// process, and no header a request wrote about itself is read.
func (s *Server) wrapRequest(handler RequestHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		gw, err := s.viewerGateway(r.Context(), r.Header.Get(WorkContextHeader), r.Method+" "+r.URL.Path)
		if err != nil {
			code := http.StatusUnauthorized
			if errors.Is(err, ErrRequestRefused) {
				code = http.StatusForbidden
			}
			writeRefusal(w, r, code, err.Error(), err)
			return
		}
		result, err := handler(r, gw)
		if err != nil {
			status, message := handlerErrorResponse(err)
			writeRefusal(w, r, status, message, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// Gateway is the viewer a handler or a tool acts for: whom the authority's
// Check said the request's Work Context is for, and the Work Contexts the
// authority issues on their behalf through this module's bindings (ForParent)
// or for this module's own work (ForBinding). A derived gateway resolves its
// Work Context per call (WorkContext), which a caller presents to the module it
// reaches itself, over gRPC through the hop.
type Gateway struct {
	// parentContext is the person's Work Context the edge sent the request
	// with: the parent every ForParent child is issued from. Never forwarded
	// as it is.
	parentContext string
	// viewer is whom the authority's Check said that context is for, and who
	// acts for them; nil on a gateway built outside a request.
	viewer *requestViewer
	// orgID is the viewer's organization, as the authority answered it. Every
	// Work Context is issued inside exactly one org.
	orgID string
	// sanitizeErrors makes this gateway hand back errors a caller may relay
	// verbatim. Set on the MCP path, where a tool's error becomes content the
	// client reads and nothing downstream can tell it from the author's own.
	sanitizeErrors bool
	// delegation is the ask this gateway acts under, nil on the one a handler
	// is given. It holds the ask rather than a capability: see delegation.
	delegation *delegation
	contexts   *workContextCache
	// host is the authority interface that checks the viewer and issues this
	// gateway's Work Contexts (authority.go).
	host *hostAuthority
	// id is this solution's manifest id, for the log line a sanitized refusal
	// writes.
	id string
}

// newGateway is the gateway every viewer reaches this runtime on, before the
// authority's Check has said who they are (viewerGateway fills that in).
func (s *Server) newGateway() *Gateway {
	return &Gateway{host: s.host, id: s.manifest.ID, contexts: newWorkContextCache()}
}

// OrgID is the viewer's organization, as the authority's Check of the request's
// Work Context answered it — never anything the request wrote about itself. It
// is the organization every Work Context this gateway is issued is inside, so
// a handler that scopes a module read to a tenant names this one rather than
// resolving another.
func (g *Gateway) OrgID() string { return g.orgID }

// --- Work Context ---
//
// A module derives tenant and subject from a signed Work Context naming it as
// the audience. Under the authority, every one this runtime acts under is
// issued by the authority: a child of the edge's context through one of this
// module's bindings, or this module's own through a binding. The runtime holds
// the string and a deadline, and decodes nothing.

// workContextRenewal is the most lead time the cache takes before a Work
// Context expires, so a call never presents one that lapses between here and
// the module's check. It is a ceiling, not a requirement on the issuer: a
// context whose whole life is shorter is reused until half its lifetime is
// gone (see hostAuthority.issue). Conflating the two would make every
// short-lived context uncacheable and turn the cache into an issue per call,
// silently.
const workContextRenewal = 10 * time.Second

// workContextMinimumLifetime is the least remaining validity an issued Work
// Context must carry to be worth presenting at all. Below this it would lapse
// mid-flight, so it is a boundary error rather than a credential.
const workContextMinimumLifetime = 5 * time.Second

// Scope is one slice of authority asked for a Work Context: what the module
// may be asked to do, on which resources, on the viewer's behalf. Empty
// ResourceIDs grants the actions across the whole ResourceKind.
type Scope struct {
	ResourceKind string
	Actions      []string
	ResourceIDs  []string
}

// workContextScope is a Scope as an ask carries it: DEEP-copied from the
// caller's Scope, so what was asked and what is issued are the same bytes for
// the life of the delegation, and its JSON is part of the cache key.
type workContextScope struct {
	ResourceKind string   `json:"resourceKind"`
	Actions      []string `json:"actions,omitempty"`
	ResourceIDs  []string `json:"resourceIds,omitempty"`
}

// askedScopesOf is an ask's scopes, DEEP-copied.
//
// A conversion would copy the slice HEADERS and leave both types pointing at
// the caller's backing arrays: a caller could hand over Scope{Actions:
// []string{"read"}}, take the delegated gateway, write "delete" into that
// array, and wait for the cached context to expire — the next issue would ask
// "delete" under the key computed for "read". So the slices are copied too.
func askedScopesOf(scopes []Scope) []workContextScope {
	wire := make([]workContextScope, len(scopes))
	for i, scope := range scopes {
		wire[i] = workContextScope{
			ResourceKind: scope.ResourceKind,
			Actions:      append([]string(nil), scope.Actions...),
			ResourceIDs:  append([]string(nil), scope.ResourceIDs...),
		}
	}
	return wire
}

// surfaced is the error a caller is handed, sanitized where the caller cannot
// be trusted to sanitize it themselves.
//
// On a handler route this returns the error unchanged: the detail is what a log
// line and an operator need, and handlerErrorResponse sanitizes at the HTTP
// boundary, which every handler response passes through.
//
// An MCP tool has no such boundary. A tool returns an error and the MCP SDK
// turns it into a CallToolResult carrying that text, *below* the middleware
// this runtime installs — so by the time anything here sees the call again the
// text is content, indistinguishable from what the author meant to say. So the
// sanitizing happens where the error leaves this runtime's hands, rather than
// where it would be too late. The detail goes to the log.
func (g *Gateway) surfaced(err error) error {
	if err == nil || !g.sanitizeErrors {
		return err
	}
	_, message := handlerErrorResponse(err)
	log.Printf("solution %q: refusing a module call for a viewer: %v", g.id, err)
	return errors.New(message)
}

// delegation is the ask a derived gateway acts under. It holds the ask and not
// the Work Context so that every call resolves a live one: a context
// snapshotted when the gateway was derived lapses while the handler still holds
// it, and the module verifies freshness on any presented context, so the call
// would be refused there rather than served.
type delegation struct {
	key string
	ask issueAsk
}

// issueAsk is what a derived gateway asks the authority for: a child of the
// viewer's Work Context through binding, narrowed to scopes (ForParent), or
// this module's own Work Context through binding in organization (ForBinding).
type issueAsk struct {
	organization string
	binding      string
	scopes       []workContextScope
	child        bool
}

// workContext resolves the Work Context this gateway acts under, having the
// authority issue one if the cache holds none that will outlive the call.
func (g *Gateway) workContext(ctx context.Context) (string, error) {
	return g.contexts.resolve(ctx, g.delegation.key, func(ctx context.Context) (string, time.Time, error) {
		return g.issue(ctx, g.delegation.ask)
	})
}

// WorkContextRefusal is the authority's refusal of an ask: the HTTP status a
// page is answered with, the authority's own reason, and the audience the ask
// named.
type WorkContextRefusal struct {
	Audience   string
	StatusCode int
	// Reason is the authority's own reason for a refusal ("the owner holds
	// nothing at this audience"), kept so the refusal names it. Only the
	// authority's refusals of the ask carry one; a failure to reach it is
	// nobody's refusal, and its text, which can name an address, is not kept.
	Reason string
	// code is the authority's gRPC status, which a Connect caller is answered
	// with rather than a code re-derived from StatusCode.
	code connect.Code
}

func (e *WorkContextRefusal) Error() string {
	message := "request failed"
	switch {
	case e.Reason != "":
		message = e.Reason
	case e.StatusCode == http.StatusUnauthorized, e.StatusCode == http.StatusForbidden:
		message = "request refused"
	case e.StatusCode == http.StatusServiceUnavailable:
		message = "the authority is unavailable"
	}
	return fmt.Sprintf("work context issue: HTTP %d: %s", e.StatusCode, message)
}

func (e *WorkContextRefusal) Unwrap() error { return &GatewayError{StatusCode: e.StatusCode} }

// issue asks the authority for the Work Context an ask names and remembers
// whom it was issued for.
func (g *Gateway) issue(ctx context.Context, ask issueAsk) (string, time.Time, error) {
	var token string
	var renew time.Time
	var principals WorkContextPrincipals
	var err error
	if ask.child {
		token, renew, principals, err = g.host.issueChild(ctx, g.parentContext, ask.binding, ask.scopes)
	} else {
		token, renew, principals, err = g.host.issueForBinding(ctx, ask.organization, ask.binding)
	}
	if err != nil {
		return "", time.Time{}, err
	}
	g.contexts.remember(token, principals)
	return token, renew, nil
}

// WorkContextPrincipals is who the authority says a Work Context acts for: the
// organization, its owner, and its current actor. They are the authority's own
// answer, never anything the handler or the browser supplied.
type WorkContextPrincipals struct {
	OrgID                   string `json:"orgId"`
	OwnerPrincipalID        string `json:"ownerPrincipalId"`
	CurrentActorPrincipalID string `json:"currentActorPrincipalId"`
}

// WorkContextPrincipals reports whom the Work Context this gateway acts under
// is for. The gateway a handler is given acts under the context the request
// carried, and reports whom the authority's Check said it is for: the person
// as owner and, on a module's tool call, that module as the current actor. A
// gateway derived by ForParent or ForBinding resolves (and if need be has
// issued) its own context exactly as a call would, and reports whom the
// authority issued it for. A handler compares them against an identity it was
// handed rather than trusting that identity.
func (g *Gateway) WorkContextPrincipals(ctx context.Context) (WorkContextPrincipals, error) {
	if g.delegation == nil && g.viewer != nil {
		return g.viewer.principals, nil
	}
	if g.delegation == nil {
		return WorkContextPrincipals{}, errors.New("this gateway acts under no work context; derive one with ForParent or ForBinding")
	}
	token, err := g.workContext(ctx)
	if err != nil {
		// Through surfaced, like ForParent's: this reaches the same issue, so
		// it produces the same errors, and a tool calling it would otherwise
		// relay the whole chain to an agent client.
		return WorkContextPrincipals{}, g.surfaced(err)
	}
	principals, ok := g.contexts.principals(token)
	if !ok || principals.OwnerPrincipalID == "" || principals.CurrentActorPrincipalID == "" || principals.OrgID == "" {
		return WorkContextPrincipals{}, errors.New("the work context issuance named no organization, owner or actor")
	}
	return principals, nil
}

// requestViewer is whom the Work Context a request carried is for, as the
// authority's Check answered it.
type requestViewer struct {
	principals WorkContextPrincipals
	actors     []string
}

// ActorChain is who acts, in order, under the Work Context the request
// carried: empty when the person acts for themselves; on a module's tool call,
// the module issued the child through its binding, last. It is the authority's
// Check of that context, never anything the request wrote, and it is empty on
// a gateway built outside a request.
func (g *Gateway) ActorChain() []string {
	if g.viewer == nil {
		return nil
	}
	return slices.Clone(g.viewer.actors)
}

// workContextCache holds the Work Contexts issued while serving one request.
// The gateway a handler receives owns it and every gateway derived from that
// one shares it, so the cache lives exactly as long as the viewer's request.
type workContextCache struct {
	mu     sync.Mutex
	minted map[string]cachedCapability
	// minting holds the issue in flight for an ask, so concurrent asks for the
	// same one wait on it instead of each running their own. A handler that
	// fans out would otherwise spend one issue per goroutine for a context
	// they all share.
	minting map[string]*pendingMint
	// Refusals persist for this viewer request; another caller must not re-ask.
	refused map[string]error
	// issuedFor holds, per issued context, whom the authority said it acts for.
	issuedFor map[string]WorkContextPrincipals
}

func (c *workContextCache) remember(token string, principals WorkContextPrincipals) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issuedFor[token] = principals
}

func (c *workContextCache) principals(token string) (WorkContextPrincipals, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	principals, ok := c.issuedFor[token]
	return principals, ok
}

func newWorkContextCache() *workContextCache {
	return &workContextCache{
		minted:    map[string]cachedCapability{},
		minting:   map[string]*pendingMint{},
		refused:   map[string]error{},
		issuedFor: map[string]WorkContextPrincipals{},
	}
}

// cachedCapability is one Work Context this gateway holds for the life of a
// request: the carrier as it travels, and when it stops being worth
// presenting. Not a Work Context — this runtime declares none of a
// capability's fields and reads none of them (see
// work_context_boundary_test.go); it holds the string and a deadline.
type cachedCapability struct {
	token string
	// reuseUntil is when this context stops being worth presenting — its
	// expiry less the renewal lead the issue already applied.
	reuseUntil time.Time
}

// pendingMint is one issue in flight. Its result fields are written before done
// is closed and read only after, so the close/receive pair orders them.
type pendingMint struct {
	done  chan struct{}
	token string
	err   error
}

// resolve returns the Work Context for one ask, running issue only when the
// cache holds none that will outlive the call and no other caller is already
// asking for it.
func (c *workContextCache) resolve(
	ctx context.Context,
	key string,
	issue func(context.Context) (string, time.Time, error),
) (string, error) {
	c.mu.Lock()
	if err := c.refused[key]; err != nil {
		c.mu.Unlock()
		return "", err
	}
	if issued, ok := c.minted[key]; ok && time.Now().Before(issued.reuseUntil) {
		c.mu.Unlock()
		return issued.token, nil
	}
	if inflight, ok := c.minting[key]; ok {
		c.mu.Unlock()
		select {
		case <-inflight.done:
			// The leader's outcome is this caller's outcome. Retrying its
			// failure here would turn one refusal into one ask per waiter.
			return inflight.token, inflight.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	inflight := &pendingMint{done: make(chan struct{})}
	c.minting[key] = inflight
	c.mu.Unlock()

	token, reuseUntil, err := issue(ctx)
	inflight.token, inflight.err = token, err

	c.mu.Lock()
	delete(c.minting, key)
	var refusal *WorkContextRefusal
	if errors.As(err, &refusal) && (refusal.StatusCode == http.StatusUnauthorized || refusal.StatusCode == http.StatusForbidden) {
		c.refused[key] = err
	}
	if err == nil {
		c.minted[key] = cachedCapability{token: token, reuseUntil: reuseUntil}
	}
	c.mu.Unlock()
	close(inflight.done)
	return token, err
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

// dialledAddresses is the non-empty addresses this process talks to, for the
// one question asked of them: does a string a tool is about to hand a client
// contain one?
// The parameter and loop variable are deliberately NOT called `address`: the
// package has a function of that name which reads the environment, and the
// environment boundary keys its resolvers by bare name — so a local called
// `address` reads to that gate as a reference to the resolver. Shadowing a
// resolver's name is confusing on its own account; the gate just says so.
func dialledAddresses(dialling ...string) []string {
	dialled := []string{}
	for _, one := range dialling {
		if strings.TrimSpace(one) != "" {
			dialled = append(dialled, one)
		}
	}
	return dialled
}
