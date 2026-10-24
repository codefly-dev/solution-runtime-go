// Package solution is a generic runtime for "solution" modules — independently
// deployed extensions that plug into a host at runtime with no build-time
// coupling. It owns everything every solution needs identically: env/config,
// obtaining this execution's credential, a plain-HTTP listener on the port
// Codefly resolves, CORS, static Module Federation asset serving, the
// capability handshake, the solution manifest, the authority contract, and
// serving the solution's MCP server to agent clients. A solution author
// supplies a manifest and one or more handlers; each handler receives a Gateway
// that forwards the caller's bearer, and ServeMCP exposes the same experience to
// an MCP client as the signed-in person.
//
// # A runtime does not register itself
//
// It used to. Two self-registrations — the manifest to the host frontend, the
// dialable upstream to the gateway — were sent every 15s, each one burning a
// single-use credential the issuer audited as a mint, so a solution that had not
// changed in a week announced itself ~11.5k times a day and the issuer's audit
// log recorded every one of them. Presence came from a process being up, which
// means a process could claim it.
//
// Presence is now delivered: a signed presence document declares which solution
// runs on which host, and the host reconciles towards it. Authority is
// delivered the same way, by a signed document naming one approved build. This
// runtime's only outbound act at boot is to obtain its own credential once, from
// the projected service-account token the platform mounts for it, bound to the
// build it is; it renews that credential when it expires and otherwise says
// nothing to anyone. Health is answered, never pushed: the host probes the
// destination its own presence document names.
//
// Nothing bridges the two models. A runtime of this generation against a host
// that still expects registrations registers nothing; a runtime of the previous
// generation against a host of this one gets 404 on endpoints that no longer
// exist, which is the intended outcome of the cutover and not a condition either
// side recovers from.
//
// This package knows nothing about any specific host or solution: what it
// depends on beyond the standard library is the Codefly SDK it resolves
// configuration through, Core, Connect for the wire, and the official MCP SDK.
package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
	"github.com/google/uuid"
)

// Manifest is the small, solution-specific description the author provides.
//
// What the host lists the solution under — its title, nav order, exposed
// module, host contract, dashboard and surfaces — is not declared here. It is
// declared once, in the file FrontendFileName names, which Frontend embeds and
// the CLI delivers in the presence document: two readers of one file cannot
// disagree, where a Go field beside a file could.
type Manifest struct {
	ID           string   // logical id / gateway service alias, e.g. "widgets-go"
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

// validateID refuses an empty id. Nothing refused one, and it was load-bearing
// in a place it does not look load-bearing: the published contract carries it
// as `Solution`, which was also the test for whether a contract had been
// resolved at all — so an empty id switched the scope ceiling off while every
// other part of the boot reported success, and a ForModule asking for no
// scopes against an undeclared audience reached the host as a viewer mint. The
// ceiling is keyed on its own flag now, and this refusal closes the way to
// produce the state.
//
// It is also what the host's presence document names this solution by, and
// what every refusal in this package identifies the process as, so an empty
// one makes the logs of a misconfigured deployment anonymous.
func (m Manifest) validateID() error {
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("this solution declares no id: Manifest.ID is what the host's presence document names it by, what the published contract reports as its own, and what every refusal here identifies this process as. Set it to the module id the composition deploys")
	}
	return nil
}

// Handler is a solution endpoint. It receives a Gateway bound to the caller's
// bearer and returns any JSON-serializable value. ClientError, GatewayError and
// Connect errors retain actionable statuses; untyped errors return 502.
type Handler func(ctx context.Context, gw *Gateway) (any, error)

// RequestHandler receives the incoming request and the same caller-bound Gateway
// as Handler. Implementations must bound and validate request bodies before use.
// Return a ClientError to reject invalid input with a 4xx status. GatewayError
// and Connect errors retain actionable statuses; untyped errors return 502.
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
	// manifest route and the MCP metadata document serve from.
	frontend frontendDeclaration
	handlers map[string]RequestHandler
	// installStep is declared before Serve, like the handlers. Outcomes and
	// in-flight calls are shared by installation ID and revision.
	installStep   func(context.Context, Installation) error
	installMu     sync.Mutex
	installations map[installationKey]*installationResult
	// installCompleted orders the terminal outcomes kept, oldest first.
	installCompleted []installationKey
	// consumed is the passthrough declaration (Consumes); passthrough is its
	// resolved routes, checked by Serve before it listens.
	consumed    []ConsumedModule
	passthrough map[string]passthroughRoute
	// mcp is the MCP server the solution declared with ServeMCP, nil when it
	// declared none; mcpRedeclared records a second ServeMCP, which the boot
	// refuses rather than letting the last call quietly be the only surface.
	mcp           *mcpSurface
	mcpRedeclared bool
	cfg           config
	// host is the authority interface, when the composition names one.
	host *hostAuthority
	// declaredContract is the authority contract the author declared
	// (Contract); contract is that contract resolved for the profile this
	// process runs under, which is what it publishes.
	declaredContract ModuleContract
	contract         effectiveContract
	// contractResolved says the boot resolved that contract, which is the only
	// thing that makes its ceilings governing.
	//
	// A flag, because the test for it was `s.contract.Solution != ""` — a
	// field that is the solution's own id, so it doubled as the sentinel for
	// "this contract came from a boot". An empty Manifest.ID therefore left the
	// ceiling switched off while everything else about the boot succeeded, and
	// ForModule accepted no scopes for an undeclared audience and minted as the
	// viewer. New() refuses an empty id now as well, so there are two
	// independent reasons this cannot recur; a value that is also a sentinel
	// has one.
	contractResolved bool
	// credential is the optional consumer-supplied SDK source. The native
	// broker is opened at boot when no consumer source was supplied. Both
	// feed the same controller through nextCredential.
	credential CredentialSource
	// authority is the frozen set of authority-bearing values this process runs
	// under, read once at boot and rechecked before every credential renewal.
	authority      *codefly.Authority
	projectionRead brokerProjectionReader
	scopedMu       sync.Mutex
	scoped         map[credentialScope]*scopedCredential
	executionMu    sync.Mutex
	execution      sealedIdentity
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
	// attestation throttles what a failed attestation says (see attestWorkload).
	attestation attestationReport
	// outbound is the client this boot makes platform requests with (see
	// outboundClient). Nil until the boot builds it.
	outbound *http.Client
	// principal is the principal this workload runs as, as the authority-bearing
	// values the platform provisioned name it. It is what the published
	// contract reports and what a delivered authority document grants to.
	principal string
}

type config struct {
	requiresAuthority bool
	listenHost        string
	port              string
	gatewayURL        string
	// authorityEndpoint is the authority interface the composition names
	// (authority/endpoint). When set, the runtime asks it instead of the saas
	// gateway (authority.go), and no gateway is required.
	authorityEndpoint string
	// dialled is every address this process talks to, assembled at boot.
	//
	// It exists so nothing has to re-read the configuration to ask "is this
	// one of ours?" — which is both a deferred configuration read the
	// environment boundary refuses, and work repeated per error result. Its
	// one consumer is withoutRuntimeAddresses, the net that stops a tool
	// telling an MCP client an address this runtime dialled.
	dialled   []string
	assetsDir string
	// mintURL is where this execution's credential is minted: the host's
	// published broker route (credentialMintPath) on the gateway endpoint the
	// composition resolved. Derived, not resolved separately, because the
	// gateway's workload endpoint serves the gateway's whole handler, the mint
	// included — and there is no override, since an override would be a
	// second destination for the projected service-account token.
	mintURL             string
	brokerInternalToken string
	// projectedTokenPath is the file the platform projects this workload's
	// service-account token into. It is re-read before every renewal, because
	// the projection is rotated under the running process and a token read once
	// at boot stops verifying long before the process stops running.
	projectedTokenPath string
	// transport is the composition's answer to whether a plaintext hop inside
	// the cell is carried by a mutually authenticated mesh, and whether this is
	// a local run — read once here and handed to the SDK's endpoint rule, which
	// is the one copy of the rule that admits http:// to the gateway. See
	// meshTransport.
	transport meshTransport
	// profile is the configuration profile this process runs under, which the
	// published contract is keyed by. A deployed environment has a profile of
	// its own (codefly-dev/core#687, fixed in core v0.7.1), so a contract that
	// declares only "local" is refused in a deployment rather than read as if
	// the deployment were a developer machine.
	profile string
	// runtimeContext is the kind of runtime Codefly says this process runs in,
	// read from one explicit signal. It is what tells a loopback MCP issuer
	// apart from a deployed one; see deployedRuntimeContext.
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
	// consumes is the api.consumes projection Codefly injected, decoded once at
	// the boundary it enters by. There is no raw string beside it: the two were
	// separate fields, and a config could then be built with only the raw one —
	// which validate() passed, because the decoded pair was empty and an empty
	// projection is a legitimate one, and the passthrough then refused every
	// declared module as if the composition projected nothing. A second
	// representation of one value is a second thing to get wrong, so there is
	// one, and newProjection is the only way to make it.
	consumes projection
	// mcp says the solution declared an MCP surface (ServeMCP), which is what
	// makes the two values below load-bearing: validate() checks them only
	// then, so a solution that serves no MCP is unaffected by a host whose
	// issuer does not resolve.
	mcp bool
	// mcpIssuerURL is the host's OAuth issuer, published as the authorization
	// server of the MCP resource (RFC 9728).
	mcpIssuerURL string
	// mcpPublicURL is the canonical public MCP URL: derived from publicURL and
	// this solution's id, or the override the composition declared. Empty when
	// neither resolved (see mcpResource).
	mcpPublicURL string
	// mcpIssuerExplicit says the issuer came from the configuration the
	// composition declared rather than from the SDK's endpoint resolution. It
	// is what tells a deployment that resolved the host's in-cluster address —
	// which validate() refuses — from one that was told the origin clients
	// authenticate against. mcpPublicExplicit says the same of the public URL,
	// which a refusal needs to name the value that fixes it.
	mcpIssuerExplicit bool
	mcpPublicExplicit bool
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

// resolveGateway resolves the host gateway's workload endpoint by role,
// independent of the host module's name (see hostAddress).
//
// The workload endpoint, not the public rest one: inside the cell every hop
// past the gateway is plain HTTP carried by the mesh, and the gateway serves
// its whole handler — the viewer routes this runtime calls through, and the
// mint that issues this execution's credential — on that endpoint. The public
// endpoint stops serving the mint, so a runtime pointed at it would boot and
// get 404 at the one request it cannot do without.
//
// One role, no fallback. It used to retry the pre-v0.0.49 `auth-sidecar` name
// when the current one did not resolve, so a solution booted against either
// host version — which is a compatibility path, and in this cutover an
// unresolved current gateway silently selecting a legacy service is worse than
// a boot that fails naming the role. A composition that still exposes only the
// old role is a composition to re-render, not a case to accommodate.
func resolveGateway(ctx context.Context, module, gateway string) string {
	return hostAddress(ctx, module, gateway, "workload", "http")
}

// projection is the api.consumes projection as this runtime holds it: the
// decoded targets and the error decoding produced, together, because they are
// one answer about one value. It is constructed only by newProjection, so
// nothing can hold targets that disagree with the text they came from.
type projection struct {
	targets []manifest.ConsumedAPI
	err     error
}

// newProjection decodes the projection at the boundary it arrives on — the
// environment, for a boot, or the test seam's own argument.
//
// Whitespace alone is not a projection, and not a defect either: a render that
// emits a bare newline for a value this solution does not set means "consumes
// nothing", so it decodes to no entries rather than to a JSON error. Refusing
// that would fail a boot over a newline. Anything else that will not decode is
// a defect in what the composition projected, and the error is kept for
// validate() to refuse by name.
func newProjection(raw string) projection {
	if strings.TrimSpace(raw) == "" {
		return projection{}
	}
	targets, err := manifest.ParseConsumedAPIs(raw)
	return projection{targets: targets, err: err}
}

// loadConfig resolves every address, port, and path through the Codefly SDK so
// nothing is hardcoded. The host it plugs into is named by Codefly-convention
// roles (overridable), and their concrete addresses are resolved from the SDK —
// the same source `codefly endpoint` and the host services themselves use.
//
// Nothing here resolves a credential. This runtime obtains one for itself, once,
// from the service-account token the platform projects for this workload (see
// credential.go); the shared cluster-internal token and the per-solution
// registration secret that preceded it are gone, along with the surfaces that
// accepted them. Nothing here resolves an identity either: the listener is
// plain HTTP, and the cell's mesh carries transport security and destination
// identity for every hop inside it.
func loadConfig(ctx context.Context, id string, initErr error) config {
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
	// Empty by default: the host is resolved by service+endpoint role, not by its
	// workspace module name (see resolveGateway). An explicit CODEFLY_HOST_MODULE
	// scopes the lookup only when a composition is genuinely ambiguous.
	hostModule := env("CODEFLY_HOST_MODULE", "")
	hostGateway := env("CODEFLY_HOST_GATEWAY", "auth-gateway")
	hostFrontend := env("CODEFLY_HOST_FRONTEND", "frontend")
	// PUBLIC_URL is back, with one consumer and a different argument behind it.
	// It went with the manifest registration it fed, where building an absolute
	// URL from it was wrong because the route a browser reaches this solution
	// through is the host's to resolve. The MCP resource identifier an agent
	// client binds its token to needs that public origin, and #49 derives it
	// from this value when no MCP configuration declares one outright.
	public := strings.TrimRight(env("PUBLIC_URL", ""), "/")

	// Own endpoint: the port Codefly assigned this service, not a fixed default.
	self := address(ctx, "", "", "http", "http")
	port := env("PORT", "")
	if port == "" && self != "" {
		port = listenPort(self)
	}

	// Host endpoints, resolved via the SDK (no localhost:port literals).
	gatewayURL := strings.TrimRight(env("GATEWAY_URL", resolveGateway(ctx, hostModule, hostGateway)), "/")
	// The host's own origin, resolved by role. Its only consumer is the MCP
	// surface's default authorization server: the registrations that used to
	// resolve it are gone.
	frontendURL := strings.TrimRight(resolveFrontend(ctx, hostModule, hostFrontend), "/")

	// Whether a plaintext hop inside the cell is carried by the mesh, and
	// whether this is a local run: the two facts the SDK's endpoint rule
	// decides on. Read here, once, and answered from the snapshot wherever
	// the rule asks — the rule is called at validation and at every mint, and
	// a configuration value is fixed at process start anyway.
	query := codefly.For(ctx)
	transport := meshTransport{local: query.IsLocalRun()}
	transport.value, transport.set, transport.err = query.WorkspaceValueIfSet(workcontext.MeshTransportGroup, workcontext.MeshTransportKey)

	internalToken, _ := query.WorkspaceSecret("module-authority", "INTERNAL_TOKEN")
	authorityEndpoint, _ := query.WorkspaceConfiguration(AuthorityInterfaceGroup, AuthorityEndpointKey)
	cfg := config{
		brokerInternalToken: strings.TrimSpace(internalToken),
		port:                port,
		listenHost:          listenHost(self),
		gatewayURL:          gatewayURL,
		authorityEndpoint:   strings.TrimSpace(authorityEndpoint),
		assetsDir:           env("ASSETS_DIR", "../fe-remote/dist"),
		dialled:             dialledAddresses(gatewayURL),
		projectedTokenPath:  strings.TrimSpace(env(ProjectedTokenFileEnvironmentVariable, DefaultProjectedTokenFile)),
		transport:           transport,
		profile:             strings.TrimSpace(env(ContractProfileEnvironmentVariable, codefly.Environment())),
		runtimeContext:      strings.TrimSpace(env(resources.RuntimeContextPrefix, "")),
		// Carried here, which the refactor that changed this function's
		// signature dropped: three refusals and a boot log exist to tell an
		// operator "the SDK resolved nothing" apart from "loading the injected
		// environment failed first", and with this left unset they all read as
		// the former. Sending someone to inspect provisioning over a variable
		// they broke themselves is the specific mistake validate() was written
		// to stop making.
		environmentLoadErr:  environmentLoadErr,
		consumerIdentityErr: consumerIdentityErr,
	}
	// The mint is a published route on the gateway this process already
	// resolved: the workload endpoint serves the gateway's whole handler. One
	// address resolved, one origin dialled; the path is the host's contract.
	if gatewayURL != "" {
		cfg.mintURL = gatewayURL + credentialMintPath
	}
	// The host is the authorization server an MCP client authenticates against,
	// so its issuer is the host's own origin — resolved by role like every
	// other host endpoint, never typed. The resolved address is the one this
	// composition reaches the host at, which is right for a local run and is an
	// in-cluster address in a deployment, where no public client could reach
	// it: that is what the declared configuration is for. The public MCP URL
	// needs no declaration at all, being derived from the two values above it.
	cfg.consumes = newProjection(env(manifest.APIConsumesEnvironmentVariable, ""))
	cfg.mcpIssuerURL, cfg.mcpIssuerExplicit = resolveMCPIssuer(ctx, frontendURL)
	cfg.mcpPublicURL, cfg.mcpPublicExplicit = resolveMCPPublicURL(ctx, public, id)
	return cfg
}

// meshTransport is the SDK's TransportSource answered from values read once at
// boot, in loadConfig, rather than from the SDK at the moment the rule asks.
//
// A snapshot is the right shape twice over. The value is a composition
// setting, fixed at process start like every other configuration value, so
// re-reading it answers the same thing. And every environment read in this
// package sits in loadConfig's call tree, where validate() governs the result
// — the rule is asked at validation and again inside every mint, and a live
// accessor captured there would be a read after boot that nothing judges.
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

// credentialMintPath is the host's published module-broker execution endpoint,
// served on the gateway's workload endpoint beside every other gateway route.
// The origin is the resolved gateway's; only the path is this runtime's
// knowledge of the host, and it is the host's published contract.
const credentialMintPath = "/modules/_work-context"

// ProjectedTokenFileEnvironmentVariable overrides where this workload's
// projected service-account token is read from, for an operator with a
// projection the resolver cannot see. DefaultProjectedTokenFile is the CLI's
// projection, which every Codefly-managed deployment mounts; the file is a
// path this process reads at every mint, never a value, because the
// projection is rotated under the running process.
const (
	ProjectedTokenFileEnvironmentVariable = "CODEFLY__WORKLOAD_TOKEN_FILE"
	DefaultProjectedTokenFile             = "/var/run/secrets/codefly/token"
)

// validate rejects a config the runtime cannot actually serve under. When
// neither the SDK nor an explicit env override resolves a value, loadConfig
// leaves it empty; without this check Serve would bind ":"+"" — which the kernel
// happily accepts as a random port — and would mint against a scheme-less URL
// like "/platform/_credential" that http.Client.Do rejects. Both are the exact
// silent no-op this whole SDK resolution effort exists to eliminate, so an
// unresolved config must fail loud at boot rather than come up looking healthy
// on the wrong port.
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
	// The gateway carries credentials: the mint presents the projected token
	// that attests which workload this process is, and every viewer call
	// carries the viewer's bearer and the capability minted for them. So it
	// has to be resolved, and it has to be a destination those may travel to.
	if c.authorityEndpoint != "" {
		// The authority answers who a viewer is and issues every Work
		// Context; there is no gateway to resolve and no broker to reach.
	} else if u, err := url.Parse(c.gatewayURL); err != nil || !u.IsAbs() || u.Host == "" {
		if c.environmentLoadErr != nil {
			return fmt.Errorf("unresolved gateway URL %q, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
				redactedURL(c.gatewayURL), c.environmentLoadErr)
		}
		return fmt.Errorf("unresolved gateway URL %q: the SDK could not resolve the host gateway's workload endpoint and no explicit GATEWAY_URL was set — declare the host's auth-gateway service, endpoint workload, as a service dependency of this backend",
			redactedURL(c.gatewayURL))
	}
	// Whether those credentials may travel to it is the SDK's rule, not one of
	// this package's: https anywhere; http only to a loopback host on a local
	// run, or to an in-cluster Service address when the composition asserts
	// internal-transport/mesh-protected=true. It is the rule the composed
	// modules apply to their own gateway value and the one the mint client
	// applies to the same origin at every mint, so a plaintext gateway is
	// refused here, at boot, by the same words that would refuse the mint.
	// Userinfo, a query and a fragment are refused by it too: a credential in
	// a URL is a secret this runtime would log at boot and net/http would
	// strip from the request, so it is disclosed and never used.
	if c.authorityEndpoint != "" {
	} else if _, err := workcontext.AdmitEndpoint(c.gatewayURL, c.transport, "gateway"); err != nil {
		return fmt.Errorf("gateway URL %q is not a destination the projected service-account token, the viewer's bearer and the capability minted for them may travel to: %w — set GATEWAY_URL, or the composition's gateway endpoint, to one that is",
			redactedURL(c.gatewayURL), err)
	}
	if c.requiresAuthority && c.authorityEndpoint == "" && c.brokerInternalToken == "" {
		return fmt.Errorf("missing module-authority/INTERNAL_TOKEN: provision the broker perimeter credential as a workspace secret")
	}
	if err := resources.ValidateConfigurationProfileName(c.profile); err != nil {
		return fmt.Errorf("unusable contract profile %q: %w — it is the Codefly environment's own name unless %s overrides it",
			c.profile, err, ContractProfileEnvironmentVariable)
	}
	// Judged whether or not this solution declares a passthrough. The
	// projection is the composition's output, so no override an operator can
	// set repairs it, and the variable it arrived in is the only handle a
	// refusal has.
	if c.consumes.err != nil {
		return fmt.Errorf("the api.consumes projection in %s cannot be decoded: %w — it is projected by the composition (`codefly run solution`), so it is fixed there; a solution that consumes nothing leaves it unset",
			manifest.APIConsumesEnvironmentVariable, c.consumes.err)
	}
	// The MCP surface's own configuration, checked here because that is where
	// boot configuration is checked. It is a no-op for a solution that declared
	// no MCP surface, which is what keeps a host whose issuer does not resolve
	// from refusing the boot of a solution that serves none.
	if err := c.validateMCP(); err != nil {
		return err
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
//
// A function of its own so what it writes can be read in a test. The redaction
// is the property, and asserting on the helper that does it left the call site
// free to pass the raw URL — which is where the secret was actually being
// written.
func (c config) logResolved() {
	if c.environmentLoadErr != nil {
		// Everything above resolved, so the load failure cost nothing this boot
		// needs — but it is still the reason a later SDK read may come back
		// empty, and it has to be said once rather than inferred from the next
		// surprise.
		log.Printf("codefly: the injected environment did not load cleanly; every SDK-resolved value that is present came from an override: %v", c.environmentLoadErr)
	}
	// Redacted, always. The SDK's rule refuses userinfo and a query, so there
	// should be nothing to hide — and a log line is the wrong place to depend
	// on a check that runs elsewhere.
	log.Printf("codefly: this execution's credential will be minted at %q, the host's broker route on the gateway's workload endpoint; a 404 there means this host does not serve its gateway's full handler on that endpoint, not that this build was refused",
		redactedURL(c.mintURL))
}

// redactedURL is a URL as it may appear in a log: url.Redacted() replaces a
// password with "xxxxx", and a query is dropped entirely, because a token in a
// query is the shape this package refuses at boot and a log line must not be
// the place that depends on that refusal having run.
func redactedURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "(unparseable)"
	}
	// An OPAQUE url prints nothing of itself.
	//
	// url.Parse("ops:SECRET@host/path") is legal and gives scheme "ops" with
	// everything after the colon as Opaque — so User is nil, RawQuery is
	// empty, and the three strips below touch nothing. The whole secret came
	// through this function unchanged, which is the one thing it exists to
	// stop. There is no safe way to describe such a value, because its
	// content is arbitrary by definition, so only the scheme is named: enough
	// for an operator to recognise what they set and nothing more.
	if parsed.Opaque != "" || parsed.Host == "" {
		if parsed.Scheme != "" {
			return parsed.Scheme + ":(redacted)"
		}
		return "(redacted)"
	}
	// Userinfo dropped entirely, not redacted. url.Redacted() masks the
	// *password* and keeps the username — so a token carried as the username,
	// which is how a great many of them are carried, came through it intact.
	parsed.User = nil
	parsed.RawQuery, parsed.Fragment = "", ""
	return parsed.String()
}

// validateSources checks the material the *selected* source needs: a consumer
// that supplied its own credential source has said where its credential comes
// from, and requiring the projected token from it as well would be requiring
// provisioning nothing reads. What no source changes is the authority identity:
// the principal, the mint audience and the projection audience are read once
// and frozen on every path, because the published contract names the
// principal, and a hook is not a way out of that.
func (s *Server) validateSources() error {
	if s.credential != nil {
		return nil
	}
	if s.cfg.projectedTokenPath != "" {
		return nil
	}
	if s.cfg.environmentLoadErr != nil {
		return fmt.Errorf("no projected service-account token path resolved, and loading Codefly's injected environment failed first: %w — the projection may well be in place; fix the environment load before treating this as missing provisioning",
			s.cfg.environmentLoadErr)
	}
	return fmt.Errorf("no projected service-account token path resolved: this process presents that token to the host to obtain its one execution credential, so it is required. The platform projects it at %s; %s overrides the path",
		DefaultProjectedTokenFile, ProjectedTokenFileEnvironmentVariable)
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
// same bearer forwarding, organisation binding and CORS as Handle.
func (s *Server) HandleRequest(path string, handler RequestHandler) *Server {
	s.handlers[path] = handler
	return s
}

// Serve resolves this process's configuration, obtains the one credential this
// execution holds, and blocks serving the solution over plain HTTP on the port
// Codefly resolved — the cell's mesh carries the hop.
//
// It registers nothing. Presence and authority are delivered to the host; this
// runtime's only outbound act is the single mint below, and the only thing it
// tells anyone about itself is what it answers when asked.
func (s *Server) Serve() error {
	ctx := context.Background()
	ln, err := s.start(ctx)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// start is the whole boot up to the listener: the declaration checks, the
// resolved configuration, the published contract, the one mint, and the
// listener on the resolved port. Split from Serve so a test
// boots the real thing on an ephemeral port — every refusal below is a refusal
// of a real boot and not of a path only tests take.
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
	// the carriers — which this one did — resolved no gateway, no frontend and
	// no port, and reported each as something the composition forgot to
	// provision. Kept, not swallowed: loadConfig separates the two failures and
	// validate() refuses each by its own cause.
	_, initErr := codefly.Init(ctx)
	if initErr != nil {
		log.Printf("codefly: init: %v", initErr)
	}
	s.cfg = loadConfig(ctx, s.manifest.ID, initErr)
	// Whether an MCP surface was declared, which is what makes the MCP
	// configuration load-bearing: validate() checks it only then, so a
	// solution serving no MCP is unaffected by a host whose issuer does not
	// resolve.
	s.cfg.mcp = s.mcp != nil
	s.cfg.requiresAuthority = mintsAuthority(s.consumed)
	if err := s.cfg.validate(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	if s.cfg.requiresAuthority {
		if err := s.validateSources(); err != nil {
			return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
		}
	}
	// After the environment is loaded: the declaration is checked against the
	// api.consumes projection Codefly injected.
	routes, err := s.validatePassthrough()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.passthrough = routes
	// The authority-bearing values first: the principal is part of what the
	// contract publishes, and a value the platform never provisioned is named
	// here rather than discovered when a mint is refused.
	if s.cfg.authorityEndpoint != "" {
		authority, err := dialAuthority(s.cfg.authorityEndpoint, s.cfg.projectedTokenPath, s.manifest.ID)
		if err != nil {
			return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
		}
		s.host = authority
		if len(s.consumed) > 0 {
			// Passthrough relays a page's call to a consumed module through the
			// saas gateway. Under the authority there is no such gateway: a
			// page reaches a module through the hop with ForModule's Work
			// Context, and nothing passes through this process.
			return nil, fmt.Errorf("solution %q consumes modules through the gateway passthrough, which the authority interface has no gateway for: call each module through the hop with Gateway.ForModule and Gateway.WorkContext", s.manifest.ID)
		}
	} else if s.cfg.requiresAuthority {
		if err := s.openAuthority(ctx); err != nil {
			return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
		}
	}
	// The client every platform request goes out on: non-proxied, pinned to
	// the gateway's origin, following no redirect. Built before the first
	// outbound act so the mint and every viewer call share it.
	s.outbound = s.outboundClient()
	// The contract this solution publishes is resolved from the same
	// declaration, under the profile this process runs in, and every value it
	// requires is named in the refusal when it is absent.
	contract, err := s.resolveContract()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.contract = contract
	s.contractResolved = true
	// Boot exposes the host-driven install endpoint without acquiring work
	// authority. Actual authority-bearing work selects its organisation and
	// installation before the first broker request.
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
	mux.HandleFunc("POST "+installationPath, s.handleInstallation)
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

	log.Printf("solution %q listening on %s (gateway=%s, profile=%s)", s.manifest.ID, ln.Addr(), redactedURL(s.cfg.gatewayURL), s.cfg.profile)
	if serveErr := srv.Serve(ln); !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}

	return nil
}

// listen binds the resolved port, or serves on the listener a test handed over
// (see boundListener).
//
// Plain TCP. Inside the cell the mesh carries transport security and
// destination identity for every hop, and admits this port only from the
// gateway's principal — so there is no certificate to present and no caller
// to verify here, and a listener that did either would be a second copy of a
// decision the cell makes for every workload. What this process still decides
// is what a caller may do once admitted, which the stamped identity headers
// and this execution's credential govern route by route.
func (c config) nativeListener() bool {
	return c.transport.local && c.runtimeContext != resources.RuntimeContextContainer && c.runtimeContext != resources.RuntimeContextKubernetes
}

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

// handleHealth reports process health without acquiring work authority.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }

const routeCredentialTimeout = 500 * time.Millisecond

// credentialFlight is one acquisition and the answer it produced.
type credentialFlight struct {
	done       chan struct{}
	credential executionCredential
	err        error
}

// credentialAskBackoff is the FIRST quiet period after a failed ask, and
// credentialAskBackoffCeiling is the longest one.
//
// Shorter than any renewal lead at the start, so the renewal a credential's
// own expiry dictates still happens on time; long enough that a stream of
// viewer requests against an unavailable issuer is one ask rather than one per
// request.
const (
	credentialAskBackoff        = time.Second
	credentialAskBackoffCeiling = 30 * time.Second
	credentialAskBackoffJitter  = 0.2
)

// credentialAskQuiet is how long the next ask is held off after `failures`
// consecutive failures: doubling, capped, with jitter.
//
// It was a FLAT one second, reset to the same value after every failure. Under
// sustained traffic against a fast-failing issuer that is one audited mint
// attempt per replica per second for as long as the outage lasts, and every
// replica on the same period — so they arrive together, which is the shape
// that turns an issuer outage into an issuer stampede. Single-flight bounds
// how many asks one replica makes at once; it does nothing about the rate, and
// nothing about the fleet.
//
// Capped at 30s, which is under every renewal lead this runtime can see, so a
// credential still renews on its own schedule once the issuer answers again. A
// credential already in hand and unexpired keeps serving throughout, which is
// why waiting longer costs nothing a viewer can see.
//
// Jitter is multiplicative and one-sided-down, so a backoff never exceeds the
// ceiling and replicas that started together stop being in phase.
func credentialAskQuiet(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	quiet := credentialAskBackoff
	for range failures - 1 {
		quiet *= 2
		if quiet >= credentialAskBackoffCeiling {
			quiet = credentialAskBackoffCeiling
			break
		}
	}
	// Deterministic enough to reason about, random enough to break phase:
	// subtract up to 20%.
	spread := 1 - credentialAskBackoffJitter*rand.Float64()
	return time.Duration(float64(quiet) * spread)
}

// usableCredential refuses a credential that authorises nothing.
//
// A source is consumer code and may hand back the zero value — a
// half-initialised client, a stub that forgot to fail — and this runtime then
// held "a credential" with no token, no seal and no expiry, booted, answered
// /health 200, and acted for viewers under it. An expired one is the same
// shape with a timestamp.
//
// The authority wrapper could not see either: it keys on the token *changing*,
// and a token that is always "" never changes.
func usableCredential(credential executionCredential) error {
	if credential == nil || credential.Token() == "" {
		return fmt.Errorf("%w: the credential source returned no credential at all (empty token), so this process holds nothing that attests which workload it is",
			workcontext.ErrMintRefused)
	}
	// GetInstallationId, not the field: Seal() returns a POINTER now, so
	// reading the field on a credential carrying no seal panics — in the one
	// check written to refuse exactly that. The getter answers "" for a nil
	// seal, which is the refusal this wants.
	if seal := credential.Seal(); seal.GetInstallationId() == "" {
		return fmt.Errorf("%w: the credential this process holds is sealed to no installation, so there is nothing for a far end to hold it to",
			workcontext.ErrMintRefused)
	}
	// No build is read off the seal. Since core's signed module manifest
	// (core #812), a Work Context carries no build seal: the host binds the
	// execution itself at mint, holding the caller's projected ServiceAccount
	// token and the pod it names against the build its applied manifest
	// approves, and refuses a mint for anything else. A runtime-side check of
	// a seal field the protocol no longer carries would refuse every valid
	// credential.
	if expiry := credential.ExpiresAt(); !time.Now().Before(expiry) {
		return fmt.Errorf("%w: the credential this process holds expired at %s",
			workcontext.ErrMintUnavailable, expiry.UTC().Format(time.RFC3339))
	}
	return nil
}

// ErrCredentialRefused and ErrCredentialUnavailable are why a route refused to
// act for a viewer: a judgement about this build, or an issuer that cannot
// answer right now. Both are 503 — this process cannot act either way — and
// they stay distinguishable because conflating them was a review blocker in
// both directions.
var (
	ErrCredentialRefused     = errors.New("this installation's workload credential has been refused")
	ErrCredentialUnavailable = errors.New("this installation's workload credential is currently unavailable")
)

// Why this runtime infers nothing from a conflict on a viewer's mint.
//
// A credential superseded before its renewal lead keeps being handed back by
// the SDK's client, which re-mints only at that lead and exposes no way to
// invalidate what it holds. Two rounds were spent building around that: a hook
// that dropped this process's belief on a 409 from the host, and then — because
// the next ask returned the same cached credential and restored the belief — a
// memory of the superseded token so the drop would stick.
//
// Both are removed, because the *trigger* was never sound. A conflict on a
// viewer's mint may mean the credential this workload presented is superseded;
// it may equally mean that viewer lacks the authority they asked for. The host
// does not distinguish the two in that answer — I wrote that down in an earlier
// round and then built on the guess anyway — and with the token remembered, one
// viewer's missing permission became a process-wide refusal to act for anybody.
// An escalating response to an ambiguous signal is worse than no response:
// before, a 409 cost that one call; after, it cost the process.
//
// So nothing is inferred. What would close it properly is a host answer that
// says which of the two it is, and a way to tell the mint client to forget what
// it cached — the second is drafted as an sdk-go issue and neither is this
// repository's to add. Until then a superseded credential is refused call by
// call by the far end, which is correct if noisy, and the renewal that replaces
// it happens on the credential's own schedule.

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
// It is a path and nothing else. It used to be an absolute URL, built from
// PUBLIC_URL or, with none set, from this process's own listen address: true in
// a browser on the developer's machine and in no other browser anywhere, so
// every deployed solution registered a manifest the product could not load.
// This runtime no longer builds it from PUBLIC_URL: the origin a browser
// reaches this solution through is named by the route in the presence document,
// which is the host's to resolve. PUBLIC_URL itself still exists, with exactly
// one consumer — the MCP resource identifier an agent client binds its token to
// (#49), which genuinely needs a public origin. Whether a runtime should derive
// the host's /solutions/<id> route even for that is an open follow-up; it is
// the one place this package encodes the host's route layout.
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

func (s *Server) wrapRequest(handler RequestHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var gw *Gateway
		if s.host != nil {
			// Under the authority the edge sends the request on with the
			// person's Work Context for this module, and who it is for is the
			// authority's Check of that context, never a header the request
			// wrote about itself. No session bearer reaches this process.
			carried := r.Header.Get(WorkContextHeader)
			if carried == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no Work Context: this page is reached through the authority's edge, which signs the person in"})
				return
			}
			viewer, err := s.host.viewer(r.Context(), carried)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
				return
			}
			gw = s.gatewayFor(http.Header{})
			gw.parentContext = carried
			gw.orgID, gw.sessionID, gw.installationID, gw.installationErr = viewer.GetTenantId(), viewer.GetSessionId(), "", nil
		} else {
			if r.Header.Get("authorization") == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer"})
				return
			}
			gw = s.gatewayFor(r.Header)
		}
		result, err := handler(r, gw)
		if err != nil {
			status, message := handlerErrorResponse(err)
			writeJSON(w, status, map[string]string{"error": message})
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

// drainAndClose consumes what is left of a response body before closing it, so
// the connection returns to the pool instead of being dropped and re-dialled on
// the next request. Bounded: a body larger than this is not worth reading to
// keep one connection.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	// Discarded deliberately: the response is already read and the caller has
	// what it came for, so a close failure changes nothing it could act on.
	_ = resp.Body.Close()
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
	// parentContext is, under the authority, the person's Work Context the
	// edge sent the request with: the parent every ForParent child is issued
	// from. Never forwarded as it is.
	parentContext string
	// carriedContext is the install call's opaque bearer, carried unchanged
	// to the host for verification. Viewer gateways never inherit an inbound
	// capability: their Work Context is minted through ForModule instead.
	carriedContext string
	// orgID is the viewer's organization, which the bearer alone does not
	// carry. A Work Context is minted inside exactly one org.
	orgID string
	// installationErr is why installationID is empty, when it is.
	installationErr error
	// sanitizeErrors makes this gateway hand back errors a caller may relay
	// verbatim. Set on the MCP path, where a tool's error becomes content the
	// client reads and nothing downstream can tell it from the author's own.
	sanitizeErrors bool
	// installationID is the installation the gateway stamped for this request,
	// which every mint this gateway runs names. Empty when none arrived, which
	// is a refusal rather than a mint under an unnamed installation. It is not
	// read from a carried capability: see viewerInstallation.
	installationID string
	// sessionID is the viewer's session, which the bearer does not carry
	// either. Accounts seals the selected organization into that session, so
	// rooting a Task in it is what makes the mint accounts journals name the
	// session that asked for it.
	sessionID string
	// delegation is the ask this gateway acts under, nil on the one a handler
	// is given. It holds the ask rather than a capability: see delegation.
	delegation *delegation
	contexts   *workContextCache
	// host, when set, is the authority interface that issues this gateway's
	// Work Contexts (authority.go).
	host *hostAuthority
	// workload is this execution's own credential, presented on the mint this
	// runtime runs for a viewer so the issuer knows which module is asking and
	// can hold the mint to the installation and binding that credential is
	// sealed to. It is never presented to a consumed module: what a module
	// verifies is the viewer's capability, and this one attests only to the
	// process that asked for it. Nil on a gateway built without one, which is
	// every gateway in a test that does not exercise the attestation.
	workload credentialAcquirer
	// id is this solution's manifest id, for the log line a failed attestation
	// writes, and report throttles that line.
	id     string
	report *attestationReport
	// transport is what this gateway dials with: the boot's authenticated
	// client, or nil on a gateway built outside a boot.
	transport http.RoundTripper

	// ceilings is the published contract's ceiling per audience, which every
	// ForModule ask is held to. Non-nil exactly when a contract was resolved,
	// which only a boot does; a derived gateway inherits it, so chaining
	// ForModule off one cannot escape it.
	ceilings map[string][]Scope
}

func newGateway(baseURL, bearer, orgID, sessionID string) *Gateway {
	return &Gateway{
		baseURL:   baseURL,
		bearer:    bearer,
		orgID:     orgID,
		sessionID: sessionID,
		contexts:  newWorkContextCache(),
	}
}

// gatewayFor is the client a handler or the passthrough is given: one bound to
// the caller the headers identify, carrying this execution's credential for the
// mints it will run.
func (s *Server) gatewayFor(header http.Header) *Gateway {
	gw := newGateway(s.cfg.gatewayURL, header.Get("authorization"), header.Get(orgHeader), header.Get(sessionHeader))
	// Kept with its reason, so ForModule can say why rather than only that it
	// is absent.
	gw.installationID, gw.installationErr = viewerInstallation(header)
	gw.id, gw.report = s.manifest.ID, &s.attestation
	gw.host = s.host
	gw.workload = func(ctx context.Context) (executionCredential, error) {
		return s.acquireForInstallation(ctx, gw.orgID, gw.installationID)
	}
	// Broker denials can concern one organisation. They must not terminate
	// unrelated installations or turn into a process-wide health failure.
	// The ceiling this process published, carried onto the gateway a handler
	// gets, so what it mints is held to what the contract claims. Resolved
	// contracts only, read off the flag the boot sets — see contractResolved
	// for why this was the solution's id and why that was wrong.
	if s.contractResolved {
		gw.ceilings = make(map[string][]Scope, len(s.contract.Bindings))
		for _, binding := range s.contract.Bindings {
			gw.ceilings[binding.Audience] = binding.Ceiling
		}
	}
	if s.outbound != nil {
		// The transport, not the client: the client's redirect policy and
		// timeout are re-applied by platformClient below, which every client
		// this gateway builds goes through. Taking .Transport alone was the
		// bug — it dropped exactly the CheckRedirect that kept credentials
		// from being re-sent to a Location.
		gw.transport = s.outbound.Transport
	}
	return gw
}

func (g *Gateway) BaseURL() string { return g.baseURL }

// OrgID is the viewer's active organization: the x-org-id identity header the
// gateway stamped from the verified bearer, never anything the browser sent.
// It is empty for a viewer with no organization selected and for an org-less
// API key. It is the organization ForModule mints in, so a handler that scopes
// a module read to a tenant names this one rather than resolving another.
func (g *Gateway) OrgID() string { return g.orgID }

// InstallationID is the installation the gateway stamped for this request: the
// x-codefly-installation-id identity header it sets from the same verified
// claims as x-org-id, the installation that admitted the viewer, never anything
// the browser sent. It is the value this runtime accepted, the one every
// ForModule mint names, so a handler placing a resource under an installation
// names this one rather than taking an id from the page.
//
// It is empty when the request carries none — an org-less caller, or a host
// that does not confine solution traffic by installation — and when the header
// is blank, which this runtime refuses rather than mints under; a refused value
// is never handed back. It is empty on the gateway an install step receives as
// well, whose installation is the Installation that step is given.
func (g *Gateway) InstallationID() string { return g.installationID }

// HTTPClient returns an http.Client that injects the caller's bearer — and, on
// a gateway derived by ForModule, the viewer's Work Context — on every request.
// During an install step it carries the supplied installation Work Context.
// Satisfies connect.HTTPClient. Advanced escape hatch — prefer Unary.
func (g *Gateway) HTTPClient() *http.Client {
	transport := bearerTransport{bearer: g.bearer, base: g.roundTripper()}
	if g.delegation != nil || g.carriedContext != "" {
		transport.acting = g
	}
	// No timeout: this client carries streams, whose bound is the method's
	// declared MaxStreamDuration on the request context, and a client timeout
	// would cut a conforming stream off mid-flight.
	return g.platformClient(transport, 0)
}

// bearerClient carries the viewer's bearer and nothing else. The mint runs on
// it rather than on HTTPClient: a capability minted for one module would
// otherwise ride along on the request that mints another's, and the edge
// verifies every presented context, so once the first lapsed it would 401 the
// very call meant to replace it.
func (g *Gateway) bearerClient() *http.Client {
	return g.platformClient(bearerTransport{bearer: g.bearer, base: g.roundTripper()}, platformRequestTimeout)
}

// platformClient is every client this gateway dials with, and it exists so
// there is one place the two properties below cannot be forgotten.
//
// **A redirect is never followed.** This was a blocker, and the shape of it is
// worth keeping written down because every piece of it looked right on its own.
// The boot's outbound client did set CheckRedirect; gatewayFor copied only its
// .Transport, so every gateway client was an http.Client literal with Go's
// default policy, which follows up to ten hops. Go copies the original
// request's headers onto a redirected one and strips only Authorization,
// WWW-Authenticate and Cookie — so the viewer's capability and the installation
// headers went along, and on the mint, this workload's own credential in
// x-codefly-work-context went with them. Worse, bearerTransport sets the bearer
// on *every* round trip, so the one header Go does strip was put straight back;
// and a 307 re-sends the body. A single `307 Location: http://elsewhere/` from
// the gateway, from accounts, or from any module the gateway relays therefore
// handed over the viewer's unscoped bearer, their capability and this
// workload's credential — in cleartext, since nothing about an http:// hop
// involves the TLS configuration that protects the first one. ErrUseLastResponse
// returns the 3xx to the caller instead: no hop, nothing re-sent.
//
// **And the request may only go to the origin this gateway was built for.**
// That is the belt to the braces: a client built anywhere without the policy
// above is still refused by the transport, which is where a property this
// serious belongs. It is also stricter than "must be https" and needs no
// special case for a test, because an http:// fake gateway is simply its own
// origin: every destination this gateway has is one host, and validate()
// already refuses a gateway URL that is not https in a real boot.
func (g *Gateway) platformClient(transport http.RoundTripper, timeout time.Duration) *http.Client {
	// No error sanitizing here, and the reason is worth writing down because I
	// tried it.
	//
	// A transport wrapper cannot remove the address: http.Client.Do wraps
	// whatever the transport returns in its own *url.Error carrying the URL,
	// after the wrapper has run. And it would be pointless if it could — the
	// author built that request from BaseURL(), so the address is already
	// theirs and the error discloses nothing they did not have.
	//
	// What the runtime must not do is hand an author an error carrying what
	// they could NOT otherwise see: the mint URL, the issuer's own words, an
	// internal dial failure from a credential ask. Those come from this
	// package and go through Gateway.surfaced. Whether an author then relays
	// their own error text to a client is their choice, like any other string
	// they return, and the runtime cannot police it without rewriting it.
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// roundTripper carries every request this gateway makes: the module reads a
// handler issues, and the mint that authenticates them.
//
// It is never http.DefaultTransport. That transport carries Proxy:
// ProxyFromEnvironment, so with HTTP(S)_PROXY set and a NO_PROXY that does not
// cover the host's in-cluster names, these requests would be dialled to an
// arbitrary egress host — carrying the viewer's bearer, the capability minted on
// their behalf, and this workload's own credential. Every target is
// composition-local, so none of it may be proxied.
//
// A gateway built by a boot carries the transport that boot configured
// (outboundClient): non-proxied, with its pooled connections bounded. One
// built outside a boot — the passthrough test seam, a unit test — falls back
// to the non-proxied default transport, and that is the only place it is used.
func (g *Gateway) roundTripper() http.RoundTripper {
	var base http.RoundTripper = unauthenticatedTransport
	if g.transport != nil {
		base = g.transport
	}
	return originPinned{base: base, origin: requestOrigin(g.baseURL)}
}

// originPinned refuses a credential-bearing request to anywhere but the one
// origin its gateway addresses.
//
// Every destination a gateway has — a module read, a transcoded call, a stream,
// the viewer's mint — is a path on the gateway it was built for, so "same
// origin as the base URL" is not a restriction on anything this runtime does.
// What it stops is a request that was *redirected* somewhere else, or built by
// a future client that forgot the policy: the credentials on these requests are
// the viewer's bearer, the capability minted for them and this workload's own,
// and the check costs a string comparison.
//
// It refuses rather than rewrites, and it refuses an unparseable or empty base
// too, since a gateway that cannot say where it dials cannot be allowed to
// carry these headers anywhere.
type originPinned struct {
	base   http.RoundTripper
	origin string
}

func (t originPinned) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.origin == "" {
		return nil, fmt.Errorf("refusing to send a credential-bearing request to %q: this gateway has no resolved origin to dial, so there is nothing to hold the destination to", r.URL.Redacted())
	}
	if got := requestOrigin(r.URL.String()); got != t.origin {
		return nil, fmt.Errorf("refusing to send a credential-bearing request to %s: this gateway dials %s, and these headers carry the viewer's bearer, the capability minted for them and this workload's own credential — a destination that is not the gateway is a redirect or a misbuilt client, never a call this runtime makes",
			got, t.origin)
	}
	return t.base.RoundTrip(r)
}

// requestOrigin is scheme://host, the unit the pin compares. A URL that does
// not parse, or names no host, has no origin and is refused by the caller.
func requestOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// unauthenticatedTransport is the non-proxied default for a gateway built
// outside a boot.
var unauthenticatedTransport = newPlatformTransport()

// newPlatformTransport is the default transport with proxying dropped.
func newPlatformTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport
}

// outboundClient is the client this runtime makes platform requests with:
// every call a handler's gateway issues, and the viewer mints they run.
//
// Plain HTTP to the gateway's workload endpoint — or https, verified against
// the system roots, where GATEWAY_URL names an edge that presents a public
// certificate. Inside the cell the mesh carries transport security and the
// destination's identity, which is why there is no anchor, no client
// certificate and no admitted-peer set here any more: each was this process
// re-deciding what the cell decides for every workload. What the mesh does not
// decide is still here. Nothing is proxied (newPlatformTransport), no redirect
// is followed, and the transport refuses a destination that is not the
// gateway's origin (originPinned): a 307 to elsewhere would otherwise hand the
// viewer's bearer, the capability minted for them and this workload's own
// credential to whatever answered.
func (s *Server) outboundClient() *http.Client {
	transport := newPlatformTransport()
	// Pool hygiene: a connection nothing sends on is dropped rather than held
	// open indefinitely.
	transport.IdleConnTimeout = outboundIdleTimeout
	return &http.Client{
		Timeout:       platformRequestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// outboundIdleTimeout is how long a pooled platform connection nobody is using
// is kept.
const outboundIdleTimeout = 30 * time.Second

// platformRequestTimeout bounds one request this runtime makes on its own
// behalf, end to end, so a host that accepts a request and never answers
// surfaces as a failure rather than a goroutine parked in Do forever.
const platformRequestTimeout = 10 * time.Second

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

// viewerInstallation is the installation a viewer's request acts under, or an
// error naming why it cannot be read.
//
// From the header the gateway stamps, and from nothing else.
//
// Round ten asked for this to be read from the capability carrier the SDK
// names, refusing rather than degrading when one cannot be read. The second
// half is right and is what this does. The first half cannot be: INBOUND, that
// carrier is caller-controlled. A browser can put a capability in
// x-codefly-work-context, and this runtime's standing property — with its own
// test, TestBrowserSuppliedWorkContextIsNeverForwarded — is that such a
// capability authenticates nothing and is never forwarded. Reading the
// installation out of it would give a caller a say in the installation their
// own mint is attributed to, which is the defect inverted rather than fixed.
//
// It is worse than useless: FromHeaders refuses a capability whose installation
// carriers are incomplete, so a caller sending a malformed one would decide
// whether the mint happens at all. That is how the change was caught — the
// forged-capability test stopped being able to mint and hung.
//
// So the stamped header is the source, on the same footing as x-org-id and
// x-session-id: the gateway replaces all three from verified claims, and a
// value a caller sent does not survive. Absent is a refusal, not a mint under
// an unnamed installation.
//
// Where a capability IS the authority being carried — outbound, where this
// runtime attaches one — the SDK's Attach puts the seal's own installation
// beside it and the far end cross-checks the two. That is the direction the
// SDK's rule is about.
func viewerInstallation(header http.Header) (string, error) {
	id := strings.TrimSpace(header.Get(workcontext.InstallationIDHeaderName))
	if id == "" {
		return "", fmt.Errorf("this request names no installation: the gateway stamps it as %s from the same verified claims it stamps %s and %s from, and none arrived",
			workcontext.InstallationIDHeaderName, orgHeader, sessionHeader)
	}
	return id, nil
}

// orgHeader carries the viewer's organization. The gateway injects it after it
// authenticates the bearer, replacing anything the caller sent.
const orgHeader = "x-org-id"

// sessionHeader carries the viewer's session, stamped from the same verified
// claims as orgHeader and replacing anything the caller sent. It is the session
// accounts sealed the selected organization into, which is why a Task is rooted
// in it rather than in a session id this runtime invents: an invented one is a
// well-formed UUID naming no session, so the capability it roots is attributable
// to nothing — neither the audit of the mint nor any check accounts makes on the
// Task it journals can tie it back to the session that asked for it.
//
// What rooting it here does NOT do is make an issued capability revocable. The
// edge verifies a presented context's signature and validity window, not the
// liveness of the session named in it, so revoking a session stops the next
// request — at the gateway's own revocation check, before any mint — while a
// capability already minted stands until its own expiry.
const sessionHeader = "x-session-id"

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

// workContextScopes is the wire form of an ask's scopes, DEEP-copied.
//
// A conversion for the struct, because the two types have the same shape by
// construction and spelling the fields out meant a field added to Scope would
// silently stop travelling — but a conversion copies the slice HEADERS and
// leaves both types pointing at the caller's backing arrays. The ask is
// retained on the delegation and its JSON is the cache key, computed once, so
// a caller could hand over Scope{Actions: []string{"read"}}, take the
// delegated gateway, write "delete" into that array, and wait for the cached
// capability to expire: the next mint serialized "delete" under the key
// computed for "read", and the ceiling had been checked against "read". No
// concurrency and no second call to ForModule.
//
// So the slices are copied too. What was checked and what is minted are then
// the same bytes for the life of the delegation, which is what makes the
// published ceiling a guarantee rather than a check on a value the caller can
// still edit.
func workContextScopes(scopes []Scope) []workContextScope {
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

// scopesOfAsk is an ask's scopes back in this package's own type, for a check
// that has to run against what will actually be minted. (askedScopes is taken:
// contract.go uses it for a declaration's union of asks.)
func scopesOfAsk(wire []workContextScope) []Scope {
	scopes := make([]Scope, len(wire))
	for i, scope := range wire {
		// A conversion: this direction only reads the ask, and the ceiling
		// check does not retain what it is handed, so sharing the arrays is
		// safe here — the copy that matters is the one on the way IN.
		scopes[i] = Scope(scope)
	}
	return scopes
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
// The Task is rooted in the viewer's own session — the one accounts sealed the
// selected organization into — so the capability names the organization the
// viewer actually switched into, and no more of the viewer's authority than
// scopes. Both boundaries come from the identity headers the gateway stamps
// from verified claims, never from the handler or from anything a browser sent.
//
// One ask mints once, however many gateways are derived for it and from however
// many goroutines: the capability is cached under the ask itself and shared with
// every gateway derived from the one the handler was given, and concurrent asks
// for it wait on the one mint in flight. That cache lives for one request, so
// the org and session in the key are fixed across it and the audience and scopes
// are what tell two asks apart. Minting is an audited event on accounts, not a
// free call.
//
// A caller the runtime cannot name both boundaries for is refused here rather
// than charged a mint accounts would refuse: each refusal carries a ClientError,
// so a handler that returns it answers 409 (no organization selected) or 403 (no
// session — an API key cannot read a composed module) instead of a generic 502.
//
// The returned gateway holds the ask, not the capability — it resolves one per
// request — so a handler may keep it for as long as it keeps the viewer's
// request. Minting here as well means an ask accounts refuses fails at this
// call rather than inside some later round trip.
func (g *Gateway) ForModule(ctx context.Context, audience string, scopes ...Scope) (*Gateway, error) {
	// The contract first, before anything about the caller: asking for
	// authority this solution never published is this solution's defect, true
	// of every caller, and it should not be reported only to the ones who
	// happen to arrive with a complete set of identity headers.
	if err := g.withinPublishedCeiling(audience, scopes); err != nil {
		return nil, err
	}
	if g.orgID == "" {
		// The gateway injects orgHeader from the caller's active org, so it is
		// present but empty for a viewer with no organization selected and for
		// an org-less API key. Naming only the absent case would send whoever
		// reads this to inspect a header the gateway demonstrably did set.
		//
		// Selecting an organization is something the caller can actually do, so
		// this answers a status that says so. As a bare error it would reach the
		// browser as the runtime's generic 502, where "pick an organization" is
		// indistinguishable from "this solution is down".
		return nil, fmt.Errorf(
			"cannot mint a work context for %q: %s is absent or empty — the gateway injects it from the caller's active org, which is empty for a viewer with no organization selected and for an org-less API key: %w",
			audience, orgHeader, &ClientError{StatusCode: http.StatusConflict, Message: "no organization selected"})
	}
	if g.sessionID == "" {
		// Same shape as the org above: the gateway stamps this header for every
		// authenticated caller and leaves it empty for one that authenticates
		// without a session — an API key names a principal and no session.
		//
		// Such a caller cannot read a composed module at all: accounts requires
		// a Task to name a session (session_id is a required UUID on StartTask),
		// and the only session id this runtime could supply is one it invented,
		// which is what made the capability attributable to nothing. Unlike the
		// org above this is not the caller's to fix, so it is forbidden rather
		// than a conflict.
		return nil, fmt.Errorf(
			"cannot mint a work context for %q: %s is absent or empty — the gateway injects it from the verified session and stamps it empty for any caller that authenticates without one: %w",
			audience, sessionHeader, &ClientError{StatusCode: http.StatusForbidden, Message: "a user session is required to read composed modules"})
	}
	if g.installationID == "" && g.host == nil {
		if g.installationErr != nil {
			return nil, g.surfaced(fmt.Errorf("cannot mint a work context for %q: %w. The host requires an installation on every mint and refuses one naming none, and an organization is not an installation — one org may hold several",
				audience, g.installationErr))
		}
		// Not a status the caller can act on, so not a ClientError: the
		// installation comes from the capability the gateway handed us, and a
		// caller cannot seal one. A viewer seeing "pick an installation" would
		// be told to fix something that is not theirs, so this surfaces as the
		// runtime's generic failure with an operator-readable reason.
		return nil, fmt.Errorf(
			"cannot mint a work context for %q: this request names no installation. The host requires one on every mint and refuses a mint naming none, and an organization is not an installation — one org may hold several. It is read from the %s header the gateway stamps from verified claims, like the org and the session beside it, so either this request did not come through the gateway or the gateway stamped none",
			audience, workcontext.InstallationIDHeaderName)
	}
	ask := startTaskRequest{
		OrgID:           g.orgID,
		InstallationID:  g.installationID,
		SessionID:       g.sessionID,
		Audience:        audience,
		AuthorityScopes: workContextScopes(scopes),
	}
	// The ask is the cache identity. The task id names one mint rather than
	// what was asked for, so it is filled in per mint, below.
	key, err := json.Marshal(ask)
	if err != nil {
		return nil, err
	}
	acting := *g
	acting.delegation = &delegation{key: string(key), ask: ask}
	if _, err := acting.workContext(ctx); err != nil {
		return nil, g.surfaced(err)
	}
	return &acting, nil
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
// text is content, indistinguishable from what the author meant to say. The
// runtime's own errors name the mint URL, the gateway URL and the issuer's
// message, because that is what a boot refusal needs; relayed to an agent
// client they are a disclosure, which executed round eight reproduced.
//
// So the sanitizing happens where the error leaves this runtime's hands,
// rather than where it would be too late. The detail goes to the log.
func (g *Gateway) surfaced(err error) error {
	if err == nil || !g.sanitizeErrors {
		return err
	}
	_, message := handlerErrorResponse(err)
	log.Printf("solution %q: refusing a module read for a viewer: %v", g.id, err)
	return errors.New(message)
}

// withinPublishedCeiling holds a mint to the contract this process published.
//
// The contract claims, in the document an operator and a renderer read, "the
// most authority this solution may ever ask for". Until this existed that was
// true of the *declaration* and nothing else: checkContract governs the
// Consumes entries, while ForModule is public, takes any audience and any
// scopes, and went straight to the mint. A solution whose handlers only call
// ForModule consumed nothing, so mintsAuthority was false, so it needed no
// profile and published an empty contract — and minted arbitrary authority
// behind it. A ceiling that governs the declaration and not the asks is a
// ceiling that governs nothing a reviewer cares about.
//
// Enforcing it here also closes the gap the other way: a solution that mints
// through ForModule now has to declare the audience and its ceiling, because an
// audience the contract does not name is refused. That is the same answer the
// boot gives for an undeclared consumed module, at the moment the authority is
// actually asked for.
//
// A gateway with no resolved contract carries no ceilings and is not held to
// one. That is a gateway built outside a boot — a unit test, the passthrough
// seam — reachable only through this package's unexported constructors, never
// by a deployed runtime: start() resolves the contract before it serves, so
// every gateway a handler is handed carries it.
func (g *Gateway) withinPublishedCeiling(audience string, scopes []Scope) error {
	if g.ceilings == nil {
		return nil
	}
	// An ask for nothing is refused rather than waved through.
	//
	// Both shapes reached the mint: ForModule with no scopes at all, and a
	// Scope naming a kind with no actions. The loop below simply had nothing to
	// check in either case, so the ceiling was satisfied by construction — and
	// what accounts does with an empty authorityScopes is its decision, not a
	// decision this runtime gets to leave to it. A capability minted for "no
	// stated authority" is either useless or the issuer's defaults, and
	// neither is a thing a reviewer approved in this contract.
	if len(scopes) == 0 {
		return fmt.Errorf("this solution asked %q for a capability with no scopes at all: name the authority the call needs, since a mint for nothing is either useless or whatever the issuer decides to grant, and the published ceiling cannot govern either: %w",
			audience, &ClientError{StatusCode: http.StatusForbidden, Message: "this solution asked for a capability with no stated authority"})
	}
	for _, scope := range scopes {
		if len(scope.Actions) == 0 {
			return fmt.Errorf("this solution asked %q for resource kind %q with no actions: an action-less scope states no authority and is inside every ceiling by construction: %w",
				audience, scope.ResourceKind, &ClientError{StatusCode: http.StatusForbidden, Message: "this solution asked for a scope with no actions"})
		}
		// Under the authority interface, a solution that publishes no ceiling — a
		// module page, which consumes nothing through passthrough and so has no
		// ceiling it could publish here — is bounded by the authority alone: what
		// the viewer holds, cut to what the audience serves. One that publishes
		// ceilings is still held to them below.
		if g.host != nil && len(g.ceilings) == 0 {
			return nil
		}
	}
	ceiling, declared := g.ceilings[audience]
	// A declared audience with an empty ceiling is a module this solution
	// publishes as minting nothing — a ViewerBearer binding carries a nil
	// ceiling and still sat in this map, so ForModule minted real authority for
	// the one kind of module the contract says mints none. The contract and the
	// mint disagreeing is the whole defect class this check exists for.
	if declared && len(ceiling) == 0 {
		return fmt.Errorf("this solution asked %q for authority, and its published contract declares that module with no ceiling at all — it is called with the viewer's bearer and mints nothing, so there is no authority to ask for: %w",
			audience, &ClientError{StatusCode: http.StatusForbidden, Message: "that module is called with the viewer's bearer and holds no minted authority"})
	}
	if !declared {
		return fmt.Errorf("this solution asked %q for authority, and its published contract names no binding for that audience: declare it — the contract is what the host derives this solution's authority from, so an audience missing from it is authority nobody approved: %w",
			audience, &ClientError{StatusCode: http.StatusForbidden, Message: "this solution holds no binding for that module"})
	}
	for _, scope := range scopes {
		if err := withinCeiling(scope, ceiling); err != nil {
			return fmt.Errorf("this solution asked %q for %s outside the ceiling its contract publishes: %w: %w",
				audience, scopeText([]Scope{scope}), err,
				&ClientError{StatusCode: http.StatusForbidden, Message: "this solution asked for more authority than its contract allows"})
		}
	}
	return nil
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
func (g *Gateway) workContext(ctx context.Context) (string, error) {
	if g.carriedContext != "" {
		return g.carriedContext, nil
	}
	return g.contexts.resolve(ctx, g.delegation.key, func(ctx context.Context) (string, time.Time, error) {
		ask := g.delegation.ask
		// The ceiling, against the ask that is about to be MINTED.
		//
		// ForModule checks before it returns, and with the scopes deep-copied
		// the two can no longer disagree — so this is not what closes that
		// hole. It is here because the check belongs at the boundary the
		// authority actually crosses: every mint passes through this function,
		// a delegation reaching it by some future path would otherwise carry
		// an unchecked ask, and the cost is a comparison against a declaration
		// already in memory.
		// A binding ask (ForBinding) names no scopes: the authority issues the
		// binding's declared headless scopes and nothing else, so the binding
		// is its ceiling and there is no asked scope to hold to this one.
		if ask.Binding == "" {
			if err := g.withinPublishedCeiling(ask.Audience, scopesOfAsk(ask.AuthorityScopes)); err != nil {
				return "", time.Time{}, err
			}
		}
		ask.TaskID = uuid.NewString()
		return g.mint(ctx, ask)
	})
}

// WorkContextRefusal carries only the HTTP status and the locally requested
// audience. Broker response diagnostics are never retained or returned.
// Code and Message were removed; consumers should inspect StatusCode.
type WorkContextRefusal struct {
	Audience   string
	StatusCode int
}

func (e *WorkContextRefusal) Error() string {
	message := "request failed"
	switch e.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		message = "request refused"
	case http.StatusServiceUnavailable:
		message = "execution not established"
	}
	return fmt.Sprintf("work context mint: HTTP %d: %s", e.StatusCode, message)
}

func (e *WorkContextRefusal) Unwrap() error { return &GatewayError{StatusCode: e.StatusCode} }

// startTaskRequest is saas.accounts.v1.StartTaskWorkContextRequest on the wire.
// The runtime speaks it as Connect JSON rather than linking the accounts client:
// a solution's host is not this package's dependency. Leaving actorPrincipalId
// unset is what makes the viewer both owner and actor of the Task.
type startTaskRequest struct {
	OrgID string `json:"orgId"`
	// InstallationID is the installation this mint acts under, which the host
	// requires and refuses a mint naming none (core's StartInput). An
	// organization is not an installation: one org may hold several, and a
	// capability minted without naming one is attributable to the org and to no
	// deployment inside it.
	//
	// For a viewer-driven mint it is the viewer's own, read from the
	// x-codefly-installation-id header the gateway stamps from verified claims
	// — on the same footing as the org and the session beside it, and replaced
	// by the gateway whatever a caller sent. NOT from the seal of a carried
	// capability: inbound that carrier is caller-controlled, and a
	// caller-supplied capability authenticates nothing here. See
	// viewerInstallation, which carries the whole argument.
	//
	// For a background or delegated call it would be the installation the
	// parent capability was sealed to, read off this execution's held
	// credential; this runtime has no such path today, because every mint it
	// makes is driven by a viewer request and ForModule refuses one without an
	// org and a session.
	InstallationID  string             `json:"installationId"`
	TaskID          string             `json:"taskId"`
	SessionID       string             `json:"sessionId"`
	Audience        string             `json:"audience"`
	AuthorityScopes []workContextScope `json:"authorityScopes"`
	// Binding, under the authority, asks for this module's own Work Context
	// through one of its declared bindings (ForBinding), or with child, for a
	// child of the viewer's through it (ForParent). The saas route has no such
	// ask, so neither is ever sent there.
	Binding string `json:"-"`
	child   bool
}

func (g *Gateway) mint(ctx context.Context, ask startTaskRequest) (string, time.Time, error) {
	if g.host != nil {
		var token string
		var renew time.Time
		var principals WorkContextPrincipals
		var err error
		switch {
		case ask.child:
			token, renew, principals, err = g.host.issueChild(ctx, g.parentContext, ask.Binding, ask.AuthorityScopes)
		case ask.Binding != "":
			token, renew, principals, err = g.host.issueForBinding(ctx, ask.OrgID, ask.Binding)
		default:
			// A person's call reaches a module as a child of the context the
			// edge sent, through a binding: ForParent.
			err = &ClientError{StatusCode: http.StatusInternalServerError, Message: "under the authority a page calls a module through one of its bindings: Gateway.ForParent"}
		}
		if err != nil {
			return "", time.Time{}, err
		}
		g.contexts.remember(token, principals)
		return token, renew, nil
	}
	body, err := json.Marshal(ask)
	if err != nil {
		return "", time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, workContextMintTimeout)
	defer cancel()
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+workContextStartTaskProcedure, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, errors.New("work context mint: request could not be constructed")
	}
	post.Header.Set("content-type", "application/json")
	// The viewer's bearer says on whose behalf; this execution's credential
	// says which module is asking. The work-context header is free on this
	// request — the capability being minted is what the answer carries, and the
	// viewer has none yet — so attesting here collides with nothing the module
	// call later presents.
	if err := attestWorkloadReporting(ctx, g.workload, g.report, post, g.id); err != nil {
		return "", time.Time{}, err
	}
	resp, err := g.bearerClient().Do(post)
	if err != nil {
		return "", time.Time{}, errors.New("work context mint: transport failed")
	}
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, &WorkContextRefusal{Audience: ask.Audience, StatusCode: resp.StatusCode}
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
		WorkContextPrincipals
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&issued); err != nil {
		return "", time.Time{}, errors.New("work context mint: invalid response")
	}
	// The capability travels as a string and is not parsed here. There is one
	// implementation of a Work Context — core's — and this runtime is not it:
	// a token this process decoded to inspect would be a second reading of a
	// format whose only authoritative reader is the verifier at the far end.
	// What this runtime checks is what it is responsible for: that a usable
	// expiry came back, so a capability is not cached under one it can never
	// reuse. The carrier refuses an unsealed capability when it is attached
	// (workcontext.Attach), which is the one check that has to happen before a
	// call rather than at the far end.
	token := issued.Token
	if strings.TrimSpace(token) == "" {
		return "", time.Time{}, fmt.Errorf("work context mint for %q returned no capability", ask.Audience)
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
		return "", time.Time{}, fmt.Errorf(
			"work context mint for %q returned no expiry: the issuer omitted expiresAt, or spelled it differently (protobuf JSON spells it expires_at, which does not decode into this field)",
			ask.Audience)
	case lifetime < workContextMinimumLifetime:
		return "", time.Time{}, fmt.Errorf(
			"work context mint for %q returned an expiry already past or less than %s away (check this host's clock against the issuer's)",
			ask.Audience, workContextMinimumLifetime)
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
			log.Print("work context mint: issued lifetime requires an earlier renewal")
		})
	}
	g.contexts.remember(token, issued.WorkContextPrincipals)
	return token, issued.ExpiresAt.Add(-lead), nil
}

// WorkContextPrincipals is who accounts says a minted capability acts for, as
// it answered the mint: the organization, the Task's owner, and its current
// actor. They are accounts' own resolution of the forwarded bearer, never
// anything the handler or the browser supplied.
type WorkContextPrincipals struct {
	OrgID                   string `json:"orgId"`
	OwnerPrincipalID        string `json:"ownerPrincipalId"`
	CurrentActorPrincipalID string `json:"currentActorPrincipalId"`
}

// WorkContextPrincipals reports whom the capability this gateway acts under was
// issued for — on a gateway derived by ForModule, resolving (and if need be
// minting) the capability exactly as a request would. A handler compares them
// against an identity it was handed rather than trusting that identity. On a
// gateway that acts under no capability it is an error.
func (g *Gateway) WorkContextPrincipals(ctx context.Context) (WorkContextPrincipals, error) {
	if g.delegation == nil {
		return WorkContextPrincipals{}, errors.New("this gateway acts under no work context; derive one with ForModule")
	}
	token, err := g.workContext(ctx)
	if err != nil {
		// Through surfaced, like ForModule's. This is ForModule's exported
		// sibling and it reaches the same mint, so it produced the same
		// errors — the mint URL, the status, the issuer's own message — and
		// handed them back unsanitized. A tool calling it relayed the whole
		// chain to an agent client, which is the disclosure ForModule's was
		// fixed for; two callers of one mint, one of them sanitized.
		//
		// Found by driving every exported Gateway method that returns an
		// error rather than by reading the one that had already been fixed.
		return WorkContextPrincipals{}, g.surfaced(err)
	}
	principals, ok := g.contexts.principals(token)
	if !ok || principals.OwnerPrincipalID == "" || principals.CurrentActorPrincipalID == "" || principals.OrgID == "" {
		return WorkContextPrincipals{}, errors.New("the work context issuance named no organization, owner or actor")
	}
	return principals, nil
}

// workContextCache holds the capabilities minted while serving one request. The
// gateway a handler receives owns it and every gateway derived from that one
// shares it, so the cache lives exactly as long as the viewer's request.
type workContextCache struct {
	mu     sync.Mutex
	minted map[string]cachedCapability
	// minting holds the mint in flight for an ask, so concurrent asks for the
	// same one wait on it instead of each running their own. A handler that
	// fans out would otherwise spend one audited mint per goroutine for a
	// capability they all share.
	minting map[string]*pendingMint
	// Refusals persist for this viewer request; another caller must not re-mint.
	refused map[string]error
	// issuedFor holds, per issued capability, whom accounts said it acts for.
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

// cachedCapability is one capability this gateway holds for the life of a
// request: the carrier as it travels, and when it stops being worth
// presenting. Not a Work Context — this runtime declares none of a
// capability's fields and reads none of them (see
// work_context_boundary_test.go); it holds the string and a deadline.
type cachedCapability struct {
	token string
	// reuseUntil is when this capability stops being worth presenting — its
	// expiry less the renewal lead mint already applied.
	reuseUntil time.Time
}

// pendingMint is one mint in flight. Its result fields are written before done
// is closed and read only after, so the close/receive pair orders them.
type pendingMint struct {
	done  chan struct{}
	token string
	err   error
}

// resolve returns the capability for one ask, running mint only when the cache
// holds none that will outlive the call and no other caller is already minting
// it.
func (c *workContextCache) resolve(
	ctx context.Context,
	key string,
	mint func(context.Context) (string, time.Time, error),
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
			// failure here would turn one refusal into one mint per waiter.
			return inflight.token, inflight.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	inflight := &pendingMint{done: make(chan struct{})}
	c.minting[key] = inflight
	c.mu.Unlock()

	token, reuseUntil, err := mint(ctx)
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

// Unary makes a typed Connect call to a fully-qualified procedure through the
// gateway. Req and Resp are generated protobuf messages; the gateway URL, the
// bearer, and the wire protocol are hidden so a handler only names a procedure
// and passes typed messages.
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
	if t.acting == nil {
		return t.base.RoundTrip(r)
	}
	token, err := t.acting.workContext(r.Context())
	if err != nil {
		// Through surfaced, because this is the mint's own error arriving by a
		// route I had argued was safe.
		//
		// I reasoned that a transport error only names an address the author
		// already holds from BaseURL(), and that is true of a dial failure. It
		// is not true of this: a capability that lapses mid-call re-mints HERE,
		// inside the round trip, so a refusal carries the issuer's status, its
		// code and its words — and http.Client.Do then wraps the whole thing
		// and hands it to the author.
		//
		// The MCP path made that a disclosure with no boundary left to catch
		// it: the SDK's typed AddTool wrapper turns a tool's returned error
		// into CallToolResult{IsError: true} and returns a NIL error, so the
		// middleware's error branch never runs and the text travels as
		// content. Sanitizing where the error leaves this runtime is the only
		// place that works, which is the same conclusion ForModule reached.
		return nil, t.acting.surfaced(err)
	}
	if err := workcontext.Attach(r, token); err != nil {
		return nil, t.acting.surfaced(err)
	}
	resp, err := t.base.RoundTrip(r)
	// NOTHING IS INFERRED FROM A 409, and that is the whole of this runtime's
	// position on it.
	//
	// A capability was dropped from the cache when a module answered 409 with
	// an installation header. That was wrong in three successive ways: any 409
	// with any installation header; then any 409 whose header named the
	// installation the capability is sealed to — and a module answering an
	// ordinary business conflict IS in that installation, so a duplicate or a
	// lost update still evicted a perfectly valid capability and the next call
	// minted again. Needless audited mints, on the one path whose purpose is
	// one mint per execution.
	//
	// The two cases are indistinguishable on the wire: a 409 means "the state
	// you were sealed to has moved" and it means "that page already exists",
	// and nothing in the response says which. Matching installation metadata
	// identifies the SCOPE of a conflict; it does not establish supersession.
	// So this runtime infers nothing and holds the capability until its own
	// expiry. A genuinely superseded one is refused call by call by the far
	// end — correct if noisy — and the renewal that replaces it happens on the
	// credential's own schedule.
	//
	// What would make an inference sound is a machine-readable discriminator
	// from the host or the verifier: follow-up 11, and nobody's to invent here.
	// AGENTS.md and this PR's body both already said there was no inference;
	// the code is what had not caught up.
	return resp, err
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

// Restored for the MCP surface, which arrived on main after this cutover
// branched and is the only caller of each now. None of the three is a
// registration: siblingURL swaps a path suffix, deployedRuntimeContext reads
// one explicit signal, and resolveFrontend resolves the host's own origin by
// role through the SDK rather than typing an address. They were deleted as
// collateral when the registrations that called them went.

// siblingURL swaps the trailing `replacing` of base for path.
//
// It paired the two endpoints of a registration exchange, which had to address
// the same gateway. Those are deleted; its one caller now is the MCP metadata
// document's URL, derived from the resource identifier by swapping that
// suffix.
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

// deployedRuntimeContext reports whether Codefly says this process runs in a
// deployment rather than on a developer machine. The signal is explicit —
// CODEFLY__RUNTIME_CONTEXT, which core's GitOps render injects (e.g.
// "kubernetes") — and never the environment name: an environment called
// "local-dogfood" or "staging" says nothing about where the process runs.
// Every runtime context `codefly run` uses on a developer machine is local;
// any other declared context is a deployment, so a new deployed kind is
// covered without a change here. Nothing declared means not deployed.
//
// PENDING codefly-dev/core v0.5.6, which injects the signal into renders:
// until a cell is rendered with it, this reports false there too.
func deployedRuntimeContext(kind string) bool {
	switch strings.ToLower(kind) {
	case "", resources.RuntimeContextNative, resources.RuntimeContextNix,
		resources.RuntimeContextContainer, resources.RuntimeContextFree:
		return false
	}
	return true
}

// resolveFrontend resolves the host frontend's http endpoint by role, like
// resolveGateway — host-module-name-agnostic.
func resolveFrontend(ctx context.Context, module, frontend string) string {
	return hostAddress(ctx, module, frontend, "http", "http")
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
