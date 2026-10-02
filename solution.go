// Package solution is a generic runtime for "solution" modules — independently
// deployed extensions that plug into a host at runtime with no build-time
// coupling. It owns everything every solution needs identically: env/config,
// obtaining this execution's credential, a listener that presents the
// workload's own identity, CORS, static Module Federation asset serving, the
// capability handshake, the solution manifest and the authority contract. A
// solution author supplies a manifest and one or more handlers; each handler
// receives a Gateway that forwards the caller's bearer.
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
// This package depends on nothing but the standard library, the Codefly SDK and
// Core, and knows nothing about any specific host or solution.
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
	"unicode"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/resources"
	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
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
	// Surfaces are what this solution offers inside a client application — a
	// Word add-in, a Slack app — rather than as a page the host renders. The
	// host's registry projects them so a client can discover, without a table
	// of its own, which solutions offer it something.
	Surfaces []Surface
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

// Surface is one offering a solution makes inside a client application.
type Surface struct {
	ID     string // unique per client, e.g. "footnote"
	Client string // client kind: word, powerpoint, excel, slack
	Title  string // what the client labels the surface with
	// Description is the longer explanation a client may show beside the title.
	// Optional, and omitted from the manifest when empty so a client renders no
	// description rather than an empty one.
	Description string
	// Module is the path, on this solution's own origin, of a self-contained ES
	// module the client loads, resolved against the origin the client loaded
	// this solution from. The check on it catches an author reaching off that
	// origin by mistake; it is not what keeps a hostile solution from doing so
	// deliberately, since a solution serves its own manifest and need not use
	// this runtime at all. The host's registry and the client's loader own that
	// boundary and have to enforce it themselves.
	Module string
	// Contract is the surface contract major this module is built against
	// (obin-ai/obin-word docs/SURFACE.md), so a client refuses a surface it
	// cannot run rather than loading it and failing inside.
	Contract int
	// Applies is "always" or a {"tagged": [...]} selector, and Events are the
	// journal namespaces the surface reconciles on. Both are carried verbatim:
	// what a tag selects and what a namespace names are the client's to
	// interpret, not this runtime's.
	Applies any
	Events  []string
}

// surfaceAppliesAlways is what an undeclared Applies is served as. A surface is
// present in the manifest either way, so leaving the slot out would not say
// "no surface" the way an absent dashboard does — it would ask every client to
// invent the same default for a surface that is otherwise fully declared.
const surfaceAppliesAlways = "always"

// surfaceClients are the client kinds a surface may declare. A client loads
// only what names it, so an unknown kind is a surface nothing will ever load —
// caught at boot rather than showing up as a solution that simply never
// appears in the add-in.
var surfaceClients = map[string]bool{"word": true, "powerpoint": true, "excel": true, "slack": true}

// validateSurfaces refuses a surface declaration no client could use. The
// author writes these in code, so every failure here is a mistake a boot should
// name rather than a condition the runtime can recover from.
func (m Manifest) validateSurfaces() error {
	// Keyed by client and id together: two clients never see each other's
	// surfaces, so the same offering carries the same id in Word and in
	// PowerPoint, and only a collision within one client is ambiguous. The id
	// and client checks below run first, so neither half of the key can contain
	// the separator and no two distinct pairs can collide into one string.
	seen := make(map[string]bool, len(m.Surfaces))
	for i, surface := range m.Surfaces {
		switch {
		case surface.ID == "":
			return fmt.Errorf("surface %d has no id", i)
		case !isSurfaceID(surface.ID):
			return fmt.Errorf("surface %q: id must be lowercase letters and digits, separated by dashes", surface.ID)
		case surface.Title == "":
			return fmt.Errorf("surface %q has no title: a client labels the surface with it, and renders a blank control without one", surface.ID)
		case !surfaceClients[surface.Client]:
			return fmt.Errorf("surface %q: unknown client kind %q", surface.ID, surface.Client)
		case seen[surface.Client+"/"+surface.ID]:
			return fmt.Errorf("surface %q declared twice for client %q: a client addresses a surface by id, so two of its own cannot share one",
				surface.ID, surface.Client)
		case surface.Contract < 1:
			// A client runs a surface only when it recognises the contract
			// major it declares, so the zero an author leaves behind is not a
			// lenient default: it is a surface every client refuses, in a boot
			// that otherwise looks entirely healthy.
			return fmt.Errorf("surface %q: contract %d is not a surface contract major; declare the major this module is built against (>= 1)",
				surface.ID, surface.Contract)
		case !isSameOriginPath(surface.Module):
			return fmt.Errorf("surface %q: module %q must be a path on this solution's own origin, e.g. %q",
				surface.ID, surface.Module, "/surfaces/"+surface.Client+"/"+surface.ID+".js")
		}
		seen[surface.Client+"/"+surface.ID] = true
	}
	return nil
}

// isSurfaceID accepts lowercase letters and digits separated by dashes. A
// leading or trailing dash is refused so that an id is never a prefix game, and
// so the empty string cannot pass by having no characters to object to.
func isSurfaceID(id string) bool {
	if id == "" {
		return false
	}
	for i, r := range id {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		if r != '-' || i == 0 || i == len(id)-1 {
			return false
		}
	}
	return true
}

// isSameOriginPath reports whether p addresses this solution's own origin: a
// rooted path and nothing else.
//
// Whether a path is rooted is decided by the parser that will resolve it — the
// client's, not Go's — and the two disagree on three inputs. A browser follows
// WHATWG URL, where a backslash beside the leading slash is read as a slash and
// what follows it as an authority, so "/\host/x.js" resolves to https://host/x.js
// while net/url reads that backslash as an ordinary path byte and reports no
// host at all; and where ASCII tab and newline are removed from the input before
// it is parsed, so "/<tab>/host/x.js" becomes protocol-relative on arrival. None
// of the three can be seen in net/url's answer, so they are refused here by
// inspecting the bytes rather than by asking net/url what it made of them.
func isSameOriginPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return false
	}
	for _, r := range p {
		if r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
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
	handlers map[string]RequestHandler
	// consumed is the passthrough declaration (Consumes); passthrough is its
	// resolved routes, checked by Serve before it listens.
	consumed    []ConsumedModule
	passthrough map[string]passthroughRoute
	cfg         config
	// declaredContract is the authority contract the author declared
	// (Contract); contract is that contract resolved for the profile this
	// process runs under, which is what it publishes.
	declaredContract ModuleContract
	contract         effectiveContract
	// identity is where the listener's workload identity comes from. Nil means
	// the one the platform projects, read from the configured files; a consumer
	// whose platform issues an identity another way supplies it with Identity.
	identity IdentitySource
	// credential is where this execution's credential comes from. Nil until
	// the boot opens the platform's mint endpoint; a test or a consumer on
	// another issuer supplies its own with Credential.
	credential CredentialSource
	// authority is the frozen set of authority-bearing values this process runs
	// under, read once at boot and rechecked before every credential renewal.
	authority *codefly.Authority
	// firstMintWindow bounds how long the boot waits for a credential the
	// issuer says is not available yet. Zero means firstMintWait. Per-server
	// rather than a package value so a test can spend the window in
	// milliseconds without every other server in the process reading the same
	// variable.
	firstMintWindow time.Duration
	// principal is the principal this workload runs as, as the authority-bearing
	// values the platform provisioned name it. It is what the published
	// contract reports and what a delivered authority document grants to.
	principal string
}

type config struct {
	port       string
	gatewayURL string
	assetsDir  string
	// mintURL is the host endpoint that mints this execution's credential, and
	// mintAudience is the audience the projected service-account token must be
	// bound to for that endpoint to accept it. Both are resolved, never
	// defaulted to a path on a guessed host.
	mintURL      string
	mintAudience string
	// projectedTokenPath is the file the platform projects this workload's
	// service-account token into. It is re-read before every renewal, because
	// the projection is rotated under the running process and a token read once
	// at boot stops verifying long before the process stops running.
	projectedTokenPath string
	// identityCertFile, identityKeyFile and trustBundleFile are the workload's
	// X.509-SVID and the anchor its peers are verified against. The listener
	// presents the first pair; there is no plain-HTTP listener to fall back to.
	identityCertFile, identityKeyFile, trustBundleFile string
	// profile is the configuration profile this process runs under, which the
	// published contract is keyed by. A deployed environment has a profile of
	// its own (codefly-dev/core#687, fixed in core v0.7.1), so a contract that
	// declares only "local" is refused in a deployment rather than read as if
	// the deployment were a developer machine.
	profile string
	// runtimeContext is the kind of runtime Codefly says this process runs
	// under (CODEFLY__RUNTIME_CONTEXT), the explicit signal validate() uses to
	// tell a deployed process from a local one. Empty when nothing injected it.
	runtimeContext string
	// environmentLoadErr is the failure, if any, of loading Codefly's injected
	// carriers. Every SDK-resolved value above is empty when that load failed,
	// so validate() must say so rather than report each empty value as
	// something the composition forgot to provision.
	environmentLoadErr error
	// apiConsumes is the api.consumes projection Codefly injected, which the
	// passthrough declaration and the published contract are both checked
	// against before the boot listens.
	apiConsumes string
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

// loadConfig resolves every address, port, and path through the Codefly SDK so
// nothing is hardcoded. The host it plugs into is named by Codefly-convention
// roles (overridable), and their concrete addresses are resolved from the SDK —
// the same source `codefly endpoint` and the host services themselves use.
//
// Nothing here resolves a credential. This runtime obtains one for itself, once,
// from the service-account token the platform projects for this workload (see
// credential.go); the shared cluster-internal token and the per-solution
// registration secret that preceded it are gone, along with the surfaces that
// accepted them.
func loadConfig(ctx context.Context) config {
	// Empty by default: the host is resolved by service+endpoint role, not by its
	// workspace module name (see resolveGateway). An explicit CODEFLY_HOST_MODULE
	// scopes the lookup only when a composition is genuinely ambiguous.
	hostModule := env("CODEFLY_HOST_MODULE", "")
	hostGateway := env("CODEFLY_HOST_GATEWAY", "auth-gateway")

	// Own endpoint: the port Codefly assigned this service, not a fixed default.
	port := env("PORT", "")
	if port == "" {
		if self := address(ctx, "", "", "http", "http"); self != "" {
			port = listenPort(self)
		}
	}

	// Host endpoints, resolved via the SDK (no localhost:port literals).
	gatewayURL := strings.TrimRight(env("GATEWAY_URL", resolveGateway(ctx, hostModule, hostGateway)), "/")

	cfg := config{
		port:       port,
		gatewayURL: gatewayURL,
		assetsDir:  env("ASSETS_DIR", "../fe-remote/dist"),
		// The mint endpoint is on the gateway the composition already resolved,
		// following the exchange this replaces: a composed solution could not
		// reach the issuer's internal listener itself, so the gateway brokered
		// it, and the credential one gateway's host mints is honoured by that
		// host and no other.
		//
		// Whether it stays brokered is NOT settled. The host (the mint's owner)
		// prefers the workload to post directly to the issuer with its
		// projected token bound to the issuer's own audience, on the grounds
		// that a broker inserts a hop whose identity the issuer then has to
		// tell apart from the pod's — and that the mesh policy which forced
		// brokering is grantable rather than a constraint to design around.
		// Neither endpoint exists yet. So this default follows the precedent
		// rather than asserting the outcome, and the override below is how a
		// deployment points at whichever one its host actually serves.
		mintURL:            env(CredentialMintURLEnvironmentVariable, gatewayURL+credentialMintPath),
		projectedTokenPath: workloadPath(ctx, ProjectedTokenFileEnvironmentVariable, WorkloadIdentityTokenFileKey),
		identityCertFile:   workloadPath(ctx, IdentityCertFileEnvironmentVariable, WorkloadIdentityCertFileKey),
		identityKeyFile:    workloadPath(ctx, IdentityKeyFileEnvironmentVariable, WorkloadIdentityKeyFileKey),
		trustBundleFile:    workloadPath(ctx, IdentityTrustBundleFileEnvironmentVariable, WorkloadIdentityTrustBundleFileKey),
		profile:            strings.TrimSpace(env(ContractProfileEnvironmentVariable, codefly.Environment())),
		runtimeContext:     strings.TrimSpace(env(resources.RuntimeContextPrefix, "")),
		apiConsumes:        env(manifest.APIConsumesEnvironmentVariable, ""),
	}
	return cfg
}

// WorkloadIdentityGroup is the workspace configuration group through which the
// platform tells this workload where its own identity material lives: the
// projected service-account token it mints its credential with, the X.509-SVID
// key pair its listener presents, and the anchor its peers are verified
// against.
//
// Paths, never material. The values this group carries are file paths, and the
// files behind them are read by this process — the token on every renewal, the
// key pair on every handshake. The SDK's own value accessors would be the wrong
// tool for the material itself: a file-carried configuration value is read once
// and kept for the life of the process (sdk-go file_carrier.go), which is
// exactly right for a configuration value and exactly wrong for a projection
// the platform rotates under a running process.
const WorkloadIdentityGroup = "workload-identity"

// The keys of WorkloadIdentityGroup. Each has an explicit environment override
// below, for an operator with a projection the resolver cannot see.
const (
	WorkloadIdentityTokenFileKey       = "TOKEN_FILE"
	WorkloadIdentityCertFileKey        = "CERT_FILE"
	WorkloadIdentityKeyFileKey         = "KEY_FILE"
	WorkloadIdentityTrustBundleFileKey = "TRUST_BUNDLE_FILE"
)

// The environment overrides for the four paths above.
const (
	ProjectedTokenFileEnvironmentVariable      = "CODEFLY__WORKLOAD_TOKEN_FILE"
	IdentityCertFileEnvironmentVariable        = "CODEFLY__WORKLOAD_IDENTITY_CERT_FILE"
	IdentityKeyFileEnvironmentVariable         = "CODEFLY__WORKLOAD_IDENTITY_KEY_FILE"
	IdentityTrustBundleFileEnvironmentVariable = "CODEFLY__WORKLOAD_IDENTITY_TRUST_BUNDLE_FILE"
)

// CredentialMintURLEnvironmentVariable overrides the host endpoint this runtime
// mints its execution credential at. Unset, it is credentialMintPath on the
// gateway the composition resolves.
const CredentialMintURLEnvironmentVariable = "CODEFLY__CREDENTIAL_MINT_URL"

// ContractProfileEnvironmentVariable overrides the configuration profile the
// published contract is read under. Unset, it is the Codefly environment's own
// name, which is how Core resolves a profile for an environment that declares
// none (resources.Environment.ConfigurationProfileNames). A deployed
// environment therefore reads its own profile rather than the developer
// machine's — the gap codefly-dev/core#687 named and core v0.7.1 closed.
const ContractProfileEnvironmentVariable = "CODEFLY__CONTRACT_PROFILE"

// credentialMintPath is where the host mints a workload's execution credential,
// relative to the gateway — the brokered shape the registration-token exchange
// this replaces also had. See the comment at its use in loadConfig: the host
// has not settled brokered-versus-direct, and this is a default, not a claim.
const credentialMintPath = "/platform/_credential"

// workloadPath resolves one of the identity paths above: an explicit
// environment override first, then the workspace configuration group the
// platform populates. Empty means neither resolved, which validate() reports by
// name — there is no default, because a default would be a path that is true on
// one platform's pod spec and nowhere else.
func workloadPath(ctx context.Context, override, key string) string {
	if value := strings.TrimSpace(env(override, "")); value != "" {
		return value
	}
	// The SDK's error is dropped because it carries no information:
	// WorkspaceConfiguration returns the same "no workspace configuration
	// value" error whether the group was never declared or the carriers it
	// lives in never loaded. The one signal that does distinguish them is
	// whether loading the environment failed at all, which Serve records in
	// config.environmentLoadErr for validate() to report.
	value, _ := codefly.For(ctx).WorkspaceConfiguration(WorkloadIdentityGroup, key)
	return strings.TrimSpace(value)
}

// deployedRuntimeContext reports whether Codefly says this process runs in a
// deployment rather than on a developer machine. The signal is explicit —
// CODEFLY__RUNTIME_CONTEXT, which core's GitOps render injects (e.g.
// "kubernetes") — and never the environment name: an environment called
// "local-dogfood" or "staging" says nothing about where the process runs.
// Every runtime context `codefly run` uses on a developer machine is local;
// any other declared context is a deployment, so a new deployed kind is
// covered without a change here. Nothing declared means not deployed.
func deployedRuntimeContext(kind string) bool {
	switch strings.ToLower(kind) {
	case "", resources.RuntimeContextNative, resources.RuntimeContextNix,
		resources.RuntimeContextContainer, resources.RuntimeContextFree:
		return false
	}
	return true
}

// loopbackURL reports whether raw names this machine: localhost (or a name
// under .localhost), a loopback IP, or the unspecified address. Such a URL is
// reachable only from the process's own host.
func loopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

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
	if p, err := strconv.Atoi(c.port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("unresolved listen port %q: set PORT or ensure the SDK resolves this service's http endpoint", c.port)
	}
	required := map[string]string{
		"gateway URL":         c.gatewayURL,
		"credential mint URL": c.mintURL,
	}
	for name, raw := range required {
		if u, err := url.Parse(raw); err != nil || !u.IsAbs() || u.Host == "" {
			if c.environmentLoadErr != nil {
				return fmt.Errorf("unresolved %s %q, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
					name, raw, c.environmentLoadErr)
			}
			if name == "credential mint URL" {
				return fmt.Errorf("unresolved credential mint URL %q: it is %s on the gateway the SDK resolves, so an unresolved gateway leaves it empty; set %s explicitly for a host the resolver cannot see",
					raw, credentialMintPath, CredentialMintURLEnvironmentVariable)
			}
			return fmt.Errorf("unresolved %s %q: the SDK could not resolve the host endpoint and no explicit override was set", name, raw)
		}
	}
	// The listener presents the workload's own identity and there is no
	// plain-HTTP listener to fall back to, so an absent identity is a refusal
	// naming the material rather than a solution that comes up unauthenticated
	// and is refused by the host for a reason the host cannot explain.
	for _, path := range []struct{ name, value, override, key string }{
		{"workload identity certificate", c.identityCertFile, IdentityCertFileEnvironmentVariable, WorkloadIdentityCertFileKey},
		{"workload identity private key", c.identityKeyFile, IdentityKeyFileEnvironmentVariable, WorkloadIdentityKeyFileKey},
		{"projected service-account token", c.projectedTokenPath, ProjectedTokenFileEnvironmentVariable, WorkloadIdentityTokenFileKey},
	} {
		if path.value != "" {
			continue
		}
		if c.environmentLoadErr != nil {
			return fmt.Errorf("no %s path resolved, and loading Codefly's injected environment failed first: %w — the projection may well be in place; fix the environment load before treating this as missing provisioning",
				path.name, c.environmentLoadErr)
		}
		return fmt.Errorf("no %s path resolved: the listener presents this workload's X.509-SVID and there is no plain-HTTP listener, so this is required. Set %s, or have the platform provision %s/%s and declare that group as a workspace-configuration dependency of this backend",
			path.name, path.override, WorkloadIdentityGroup, path.key)
	}
	if err := resources.ValidateConfigurationProfileName(c.profile); err != nil {
		return fmt.Errorf("unusable contract profile %q: %w — it is the Codefly environment's own name unless %s overrides it",
			c.profile, err, ContractProfileEnvironmentVariable)
	}
	if c.environmentLoadErr != nil {
		// Everything above resolved, so the load failure cost nothing this boot
		// needs — but it is still the reason a later SDK read may come back
		// empty, and it has to be said once rather than inferred from the next
		// surprise.
		log.Printf("codefly: the injected environment did not load cleanly; every SDK-resolved value that is present came from an override: %v", c.environmentLoadErr)
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

// Serve resolves this process's configuration, obtains the one credential this
// execution holds, and blocks serving the solution over TLS.
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
// listener that presents this workload's identity. Split from Serve so a test
// boots the real thing on an ephemeral port — every refusal below is a refusal
// of a real boot and not of a path only tests take.
func (s *Server) start(ctx context.Context) (net.Listener, error) {
	// Before anything the environment owns: a surface or a contract the author
	// declared wrong is wrong in every environment, and saying so first keeps
	// that mistake from reading as one more unresolved address.
	if err := s.manifest.validateSurfaces(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	// The SDK owns environment resolution: load Codefly's injected carriers so
	// endpoint and workspace-configuration lookups resolve from them (falling
	// back to the local native workspace map when not running under the
	// runtime). Kept, not swallowed: when this fails every SDK-resolved value
	// below comes back empty, and validate() would otherwise report each one as
	// something the composition forgot to provision.
	environmentLoadErr := codefly.LoadEnvironmentVariables()
	if environmentLoadErr != nil {
		log.Printf("codefly: load environment: %v", environmentLoadErr)
	}
	s.cfg = loadConfig(ctx)
	s.cfg.environmentLoadErr = environmentLoadErr
	if err := s.cfg.validate(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
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
	if err := s.openAuthority(ctx); err != nil {
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
	// One mint per execution, before the listener is up. A runtime that cannot
	// obtain its credential has no authority to serve anything with, and the
	// model it serves under has nothing for it to retry against: its presence
	// was declared by a document it did not write, and a refusal here says that
	// document does not name this build. So it reports the refusal and exits
	// non-zero, for the orchestrator to restart or the delivery to be fixed —
	// it never loops, and it never comes up serving without one.
	if err := s.openCredential(ctx); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
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
	mux.HandleFunc(HealthPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	for path, handler := range s.handlers {
		mux.HandleFunc(path, withCORS(s.wrapRequest(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", withCORSHandler(s.assetsHandler())))
	if err := s.mountPassthrough(mux); err != nil {
		return err
	}

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	log.Printf("solution %q listening on :%s (gateway=%s, profile=%s)", s.manifest.ID, s.cfg.port, s.cfg.gatewayURL, s.cfg.profile)
	if serveErr := srv.Serve(ln); !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	return nil
}

// HealthPath is where this runtime answers a health probe. It is a plain 200 on
// the listener the presence document names, which is the whole of this
// runtime's part in being observed: the host decides whether this binding is
// healthy, and nothing this process says can make it present.
const HealthPath = "/health"

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
			"manifestUrl":   s.frontendManifestURL(),
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
	if len(s.manifest.Surfaces) > 0 {
		surfaces := make([]any, 0, len(s.manifest.Surfaces))
		for _, surface := range s.manifest.Surfaces {
			entry := map[string]any{
				"id":       surface.ID,
				"client":   surface.Client,
				"title":    surface.Title,
				"module":   surface.Module,
				"contract": surface.Contract,
				"applies":  surface.Applies,
			}
			if surface.Applies == nil {
				entry["applies"] = surfaceAppliesAlways
			}
			// Absent, these two say something a client can act on — no
			// description to show, nothing to reconcile on — where a null would
			// only be a slot the client still has to interpret.
			if surface.Description != "" {
				entry["description"] = surface.Description
			}
			if len(surface.Events) > 0 {
				entry["events"] = surface.Events
			}
			surfaces = append(surfaces, entry)
		}
		m["surfaces"] = surfaces
	}
	return m
}

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
// PUBLIC_URL is gone with the registration it fed: the origin a browser reaches
// this solution through is named by the route in the presence document, which
// is the host's to resolve.
func (s *Server) frontendManifestURL() string {
	return federationManifestPath
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
		result, err := handler(r, s.gatewayFor(r.Header))
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
// the next beat. Bounded: a body larger than this is not worth reading to keep
// one connection.
func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
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
	// sessionID is the viewer's session, which the bearer does not carry
	// either. Accounts seals the selected organization into that session, so
	// rooting a Task in it is what makes the mint accounts journals name the
	// session that asked for it.
	sessionID string
	// delegation is the ask this gateway acts under, nil on the one a handler
	// is given. It holds the ask rather than a capability: see delegation.
	delegation *delegation
	contexts   *workContextCache
	// workload is this execution's own credential, presented on the mint this
	// runtime runs for a viewer so the issuer knows which module is asking and
	// can hold the mint to the installation and binding that credential is
	// sealed to. It is never presented to a consumed module: what a module
	// verifies is the viewer's capability, and this one attests only to the
	// process that asked for it. Nil on a gateway built without one, which is
	// every gateway in a test that does not exercise the attestation.
	workload CredentialSource
	// id is this solution's manifest id, for the log line a failed attestation
	// writes.
	id string
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
	gw.workload, gw.id = s.credential, s.manifest.ID
	return gw
}

func (g *Gateway) BaseURL() string { return g.baseURL }

// OrgID is the viewer's active organization: the x-org-id identity header the
// gateway stamped from the verified bearer, never anything the browser sent.
// It is empty for a viewer with no organization selected and for an org-less
// API key. It is the organization ForModule mints in, so a handler that scopes
// a module read to a tenant names this one rather than resolving another.
func (g *Gateway) OrgID() string { return g.orgID }

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
// is composition-local (its address is resolved from the SDK's endpoint map), so
// none of this may be proxied.
var gatewayTransport = newPlatformTransport()

// newPlatformTransport is the default transport with proxying dropped: what
// every request to a composition-local platform endpoint is carried on, whether
// it presents the viewer's bearer (the gateway) or this workload's own
// projected token (the mint).
func newPlatformTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return transport
}

// platformClient carries the requests this runtime makes on its own behalf —
// today, the single credential mint. It is deliberately not http.DefaultClient
// and not a client a consumer can reach.
//
// No proxy, for the reason above: this request carries the projected
// service-account token that attests which workload this process is, and every
// target is composition-local.
//
// No redirects, either. net/http strips only Authorization, WWW-Authenticate
// and Cookie when a redirect crosses to another host; every other header — the
// token carrier included — is copied to the new target verbatim, and a 307/308
// re-sends the body with them. So anything able to answer at the mint URL with
// a Location (a gateway defect, an SSRF through it, a stale Service or DNS
// record claiming that name) would be handed the credential that proves this
// workload's identity, and the theft would look like an ordinary successful
// mint. The mint endpoint has no reason to redirect, so a redirect is surfaced
// as the response it is and never followed.
//
// And a Timeout, so a host that accepts the mint and never answers surfaces as
// a failed boot rather than a process parked in Do forever with no listener and
// no log.
var platformClient = &http.Client{
	Timeout:       platformRequestTimeout,
	Transport:     newPlatformTransport(),
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// platformRequestTimeout bounds one request this runtime makes on its own
// behalf, end to end.
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
	ask := startTaskRequest{
		OrgID:           g.orgID,
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
func (g *Gateway) workContext(ctx context.Context) (workcontext.WorkContextToken, error) {
	return g.contexts.resolve(ctx, g.delegation.key, func(ctx context.Context) (workcontext.WorkContextToken, time.Time, error) {
		ask := g.delegation.ask
		ask.TaskID = uuid.NewString()
		return g.mint(ctx, ask)
	})
}

// WorkContextRefusal is the issuer's refusal to mint a Work Context: most
// often an authority the viewer does not hold ("owner is not allowed
// kind:action at requested scope"). It keeps the issuer's Connect code and
// message, so a caller can tell "you lack this permission" from "the gateway
// never routed the mint", and unwraps to the GatewayError it has always been.
type WorkContextRefusal struct {
	Audience   string
	StatusCode int
	// Code is the issuer's Connect code ("permission_denied"), when it sent one.
	Code    string
	Message string
}

func (e *WorkContextRefusal) Error() string {
	return fmt.Sprintf("work context mint for %q rejected (status %d, %q): %s", e.Audience, e.StatusCode, e.Code, e.Message)
}

func (e *WorkContextRefusal) Unwrap() error { return &GatewayError{StatusCode: e.StatusCode} }

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

func (g *Gateway) mint(ctx context.Context, ask startTaskRequest) (workcontext.WorkContextToken, time.Time, error) {
	body, err := json.Marshal(ask)
	if err != nil {
		return workcontext.WorkContextToken{}, time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, workContextMintTimeout)
	defer cancel()
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+workContextStartTaskProcedure, bytes.NewReader(body))
	if err != nil {
		return workcontext.WorkContextToken{}, time.Time{}, err
	}
	post.Header.Set("content-type", "application/json")
	// The viewer's bearer says on whose behalf; this execution's credential
	// says which module is asking. The work-context header is free on this
	// request — the capability being minted is what the answer carries, and the
	// viewer has none yet — so attesting here collides with nothing the module
	// call later presents.
	attestWorkload(ctx, g.workload, post, g.id)
	resp, err := g.bearerClient().Do(post)
	if err != nil {
		return workcontext.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q: %w", ask.Audience, err)
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
		return workcontext.WorkContextToken{}, time.Time{}, &WorkContextRefusal{
			Audience: ask.Audience, StatusCode: resp.StatusCode, Code: refusal.Code, Message: refusal.Message,
		}
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
		WorkContextPrincipals
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return workcontext.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q returned invalid json: %w", ask.Audience, err)
	}
	token, err := workcontext.ParseWorkContextToken(issued.Token)
	if err != nil {
		return workcontext.WorkContextToken{}, time.Time{}, fmt.Errorf("work context mint for %q returned an unusable token: %w", ask.Audience, err)
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
		return workcontext.WorkContextToken{}, time.Time{}, fmt.Errorf(
			"work context mint for %q returned no expiry: the issuer omitted expiresAt, or spelled it differently (protobuf JSON spells it expires_at, which does not decode into this field)",
			ask.Audience)
	case lifetime < workContextMinimumLifetime:
		return workcontext.WorkContextToken{}, time.Time{}, fmt.Errorf(
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
		return WorkContextPrincipals{}, err
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
	minted map[string]issuedWorkContext
	// minting holds the mint in flight for an ask, so concurrent asks for the
	// same one wait on it instead of each running their own. A handler that
	// fans out would otherwise spend one audited mint per goroutine for a
	// capability they all share.
	minting map[string]*pendingMint
	// issuedFor holds, per issued capability, whom accounts said it acts for.
	issuedFor map[string]WorkContextPrincipals
}

func (c *workContextCache) remember(token workcontext.WorkContextToken, principals WorkContextPrincipals) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issuedFor[token.Encoded()] = principals
}

func (c *workContextCache) principals(token workcontext.WorkContextToken) (WorkContextPrincipals, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	principals, ok := c.issuedFor[token.Encoded()]
	return principals, ok
}

func newWorkContextCache() *workContextCache {
	return &workContextCache{
		minted:    map[string]issuedWorkContext{},
		minting:   map[string]*pendingMint{},
		issuedFor: map[string]WorkContextPrincipals{},
	}
}

type issuedWorkContext struct {
	token workcontext.WorkContextToken
	// reuseUntil is when this capability stops being worth presenting — its
	// expiry less the renewal lead mint already applied.
	reuseUntil time.Time
}

// pendingMint is one mint in flight. Its result fields are written before done
// is closed and read only after, so the close/receive pair orders them.
type pendingMint struct {
	done  chan struct{}
	token workcontext.WorkContextToken
	err   error
}

// resolve returns the capability for one ask, running mint only when the cache
// holds none that will outlive the call and no other caller is already minting
// it.
func (c *workContextCache) resolve(
	ctx context.Context,
	key string,
	mint func(context.Context) (workcontext.WorkContextToken, time.Time, error),
) (workcontext.WorkContextToken, error) {
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
			return workcontext.WorkContextToken{}, ctx.Err()
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
		if err := workcontext.AttachWorkContext(r, token); err != nil {
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
