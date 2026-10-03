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
	"crypto/tls"
	"crypto/x509"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	ID            string   // logical id / gateway service alias, e.g. "widgets-go"
	Title         string   // nav title, e.g. "Widgets · GO"
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
	// Contract is the surface contract major this module is built against, as
	// the host client's own surface documentation defines it, so a client
	// refuses a surface it cannot run rather than loading it and failing
	// inside. Named generically on purpose: this runtime is the generic one,
	// and the comment used to point at one product's repository.
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
	// The solution's own id first. Nothing refused an empty one, and it was
	// load-bearing in a place it does not look load-bearing: the published
	// contract carries it as `Solution`, which was also the test for whether a
	// contract had been resolved at all — so an empty id switched the scope
	// ceiling off while every other part of the boot reported success, and a
	// ForModule asking for no scopes against an undeclared audience reached the
	// host as a viewer mint. The ceiling is keyed on its own flag now, and this
	// refusal closes the way to produce the state.
	//
	// It is also what the host's presence document names this solution by, and
	// what every refusal in this package identifies the process as, so an empty
	// one makes the logs of a misconfigured deployment anonymous.
	if strings.TrimSpace(m.ID) == "" {
		return fmt.Errorf("this solution declares no id: Manifest.ID is what the host's presence document names it by, what the published contract reports as its own, and what every refusal here identifies this process as. Set it to the module id the composition deploys")
	}
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
	// identity is where the listener's workload identity comes from. Nil means
	// the one the platform projects, read from the configured files; a consumer
	// whose platform issues an identity another way supplies it with Identity.
	identity IdentitySource
	// identityConfig is the resolved, posture-checked configuration from that
	// source: one resolution serving the listener and the outbound client, so
	// the two cannot be different identities.
	identityConfig *tls.Config
	// credential is where this execution's credential comes from. Nil until
	// the boot opens the platform's mint endpoint; a test or a consumer on
	// another issuer supplies its own with Credential.
	credential CredentialSource
	// authority is the frozen set of authority-bearing values this process runs
	// under, read once at boot and rechecked before every credential renewal.
	authority *codefly.Authority
	// terminal is closed the first time the issuer answers a renewal with a
	// judgement no retry can change. It makes health fail and serve return,
	// because a process holding a credential the host has stopped honouring
	// cannot act for anyone and nothing it does locally changes that.
	terminal     chan struct{}
	terminalOnce sync.Once
	terminalErr  atomic.Pointer[error]
	// credentialValidUntil is when the credential this process last obtained
	// expires, in Unix nanoseconds. It is what decides a route's answer when
	// the source does not respond inside the route's bound: see
	// credentialWithin.
	credentialValidUntil atomic.Int64
	// handshakeTimeout overrides platformHandshakeTimeout, for a test that
	// would otherwise spend the real one. Unset means the constant, as
	// firstMintWindow does for the credential window.
	handshakeTimeout time.Duration
	// attestation throttles what a failed attestation says (see attestWorkload).
	attestation attestationReport
	// outbound is the authenticated client this boot makes platform requests
	// with (see outboundClient). Nil until the boot builds it.
	outbound *http.Client
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
	// mintURL is the host endpoint that mints this execution's credential. The
	// audience the projected token must be bound to is read through the SDK's
	// authority reader and frozen (see openAuthority), not carried here: there
	// used to be a mintAudience field beside this one, unread by anything, and
	// its comment claimed both were "resolved, never defaulted" while mintURL
	// does carry a default path.
	mintURL string
	// projectedTokenPath is the file the platform projects this workload's
	// service-account token into. It is re-read before every renewal, because
	// the projection is rotated under the running process and a token read once
	// at boot stops verifying long before the process stops running.
	projectedTokenPath string
	// identityCertFile, identityKeyFile and trustBundleFile are the workload's
	// X.509-SVID and the anchor its peers are verified against. The listener
	// presents the first pair; there is no plain-HTTP listener to fall back to.

	identityCertFile, identityKeyFile, trustBundleFile string
	// allowedCallersFile is the path to the set of identities this listener
	// admits, one per line or comma-separated. Authentication says a caller
	// holds a certificate from the cell's anchor; this says which of them may
	// call, which is a different question and the one the host's own route
	// admission answers for everybody else.
	//
	// A path, read per handshake, for the reason the trust anchor beside it is
	// one. A snapshot of an admission decision is the same defect as a
	// snapshotted trust anchor: removing a compromised consumed module from the
	// provisioned set would leave this listener admitting it for the life of the
	// process. Resolving the set through the SDK's value accessor on every
	// handshake is not live, whatever it looks like — a
	// configuration *value*, inline or file-carried, is fixed at process start
	// (sdk-go file_carrier.go reads the file once and keeps it), so
	// re-resolution returned the boot answer forever and the refusal branch
	// below was unreachable in any deployment. The file is this process's to
	// read, like the bundle, which is what makes the claim true instead of
	// documented.
	//
	// The asymmetry is the one peerAnchor records: serving a stale *leaf*
	// refuses callers who should be let in, judging by a stale *admission* lets
	// in callers who should be refused.
	allowedCallersFile string
	// admissionConflict is set when both an override and the platform answered
	// for an admission set. See conflictingAdmissionSources.
	admissionConflict error
	// platformPeersFile is the path to the set of identities this runtime
	// accepts *outbound*: the mint and the gateway. It is the mirror of
	// allowedCallersFile and it exists for the same reason — every workload in
	// the cell holds a certificate from the same anchor, so verifying the chain
	// and the hostname says a destination is some workload the platform issued
	// for, not that it is the platform. A neighbouring workload holding a
	// certificate valid for the gateway's hostname completed this handshake and
	// was handed the projected token.
	// mintPeersFile and gatewayPeersFile are the identities this runtime
	// accepts at each of the two destinations it dials, one set per
	// destination.
	//
	// One set for both was the previous shape, and it meant the gateway's
	// identity was accepted at the mint's address and the mint's at the
	// gateway's. The set already excluded every other workload in the cell,
	// which was the finding it was added for — but "the platform" is not one
	// party, and a set that spans two parties authorises each of them to stand
	// in for the other. The maximum-security answer is one authorization set
	// per destination, and a dial to anything that is neither is refused
	// outright: this runtime has exactly two destinations.
	mintPeersFile, gatewayPeersFile string
	// profile is the configuration profile this process runs under, which the
	// published contract is keyed by. A deployed environment has a profile of
	// its own (codefly-dev/core#687, fixed in core v0.7.1), so a contract that
	// declares only "local" is refused in a deployment rather than read as if
	// the deployment were a developer machine.
	profile string
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

// resolveGateway resolves the host gateway's rest endpoint by role, independent
// of the host module's name (see hostAddress).
//
// One role, no fallback. It used to retry the pre-v0.0.49 `auth-sidecar` name
// when the current one did not resolve, so a solution booted against either
// host version — which is a compatibility path, and in this cutover an
// unresolved current gateway silently selecting a legacy service is worse than
// a boot that fails naming the role. A composition that still exposes only the
// old role is a composition to re-render, not a case to accommodate.
func resolveGateway(ctx context.Context, module, gateway string) string {
	return hostAddress(ctx, module, gateway, "rest", "rest")
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
		// No default, because there is nothing to default to. Whether the mint
		// stays brokered through the gateway is not settled — the host prefers
		// the workload to post directly to the issuer with its projected token
		// bound to the issuer's own audience, and neither endpoint exists yet.
		// Deriving a path on the resolved gateway and labelling it a guess is
		// not an answer: this is the address
		// this runtime POSTs the projected service-account token to, the
		// strongest statement it can make about which workload it is, and a
		// guessed address for that is the one thing fail-closed does not
		// permit. It is refused at boot until something resolves it, which is
		// how this package already treats a token-exchange URL it cannot pair.
		mintURL:            strings.TrimSpace(env(CredentialMintURLEnvironmentVariable, "")),
		projectedTokenPath: workloadPath(ctx, ProjectedTokenFileEnvironmentVariable, WorkloadIdentityTokenFileKey),
		identityCertFile:   workloadPath(ctx, IdentityCertFileEnvironmentVariable, WorkloadIdentityCertFileKey),
		identityKeyFile:    workloadPath(ctx, IdentityKeyFileEnvironmentVariable, WorkloadIdentityKeyFileKey),
		trustBundleFile:    workloadPath(ctx, IdentityTrustBundleFileEnvironmentVariable, WorkloadIdentityTrustBundleFileKey),
		allowedCallersFile: workloadPath(ctx, IdentityAllowedCallersFileEnvironmentVariable, WorkloadIdentityAllowedCallersFileKey),
		mintPeersFile:      workloadPath(ctx, IdentityMintPeersFileEnvironmentVariable, WorkloadIdentityMintPeersFileKey),
		gatewayPeersFile:   workloadPath(ctx, IdentityGatewayPeersFileEnvironmentVariable, WorkloadIdentityGatewayPeersFileKey),
		profile:            strings.TrimSpace(env(ContractProfileEnvironmentVariable, codefly.Environment())),
		apiConsumes:        env(manifest.APIConsumesEnvironmentVariable, ""),
	}
	// Two sources for one authorization fact are refused, not ranked.
	//
	// Every other path here takes the override first and the provisioned value
	// second, which is right for a path: an operator with a deployment the
	// resolver cannot see needs the escape hatch, and the worst case is this
	// process reading its own material from somewhere else. Admission is not
	// that. An override that silently outranks the platform's answer is how a
	// caller set gets widened with nothing recording that the platform's
	// decision was not the one in force — and logging which one won, which is
	// what the previous revision did, reports the conflict without resolving
	// it.
	//
	// So: either source may answer, and both answering is an error naming
	// both. It is the stance the SDK already takes on the same question — a
	// value delivered inline and by file carrier is "two sources for one fact
	// and are refused" (file_carrier.go) — applied to the one kind of value
	// where being wrong admits a caller.
	cfg.admissionConflict = conflictingAdmissionSources(ctx)
	return cfg
}

// conflictingAdmissionSources is the error validate() reports when any value in
// the identity group is answered by both an operator override and the
// platform's provisioning.
//
// All of them, not only the two admission sets. The override that outranks the
// platform silently was found first on the caller set, and the same argument
// reaches the rest of the group: a substituted *trust bundle* widens admission
// exactly as much as a substituted caller list, and a substituted key pair
// changes who this process is. The two sets were simply where it was noticed.
func conflictingAdmissionSources(ctx context.Context) error {
	for _, admission := range []struct{ what, override, key string }{
		{"allowed callers", IdentityAllowedCallersFileEnvironmentVariable, WorkloadIdentityAllowedCallersFileKey},
		{"credential mint peer identity", IdentityMintPeersFileEnvironmentVariable, WorkloadIdentityMintPeersFileKey},
		{"gateway peer identity", IdentityGatewayPeersFileEnvironmentVariable, WorkloadIdentityGatewayPeersFileKey},
		{"peer trust anchor", IdentityTrustBundleFileEnvironmentVariable, WorkloadIdentityTrustBundleFileKey},
		{"workload identity certificate", IdentityCertFileEnvironmentVariable, WorkloadIdentityCertFileKey},
		{"workload identity private key", IdentityKeyFileEnvironmentVariable, WorkloadIdentityKeyFileKey},
		{"projected service-account token", ProjectedTokenFileEnvironmentVariable, WorkloadIdentityTokenFileKey},
	} {
		overridden := strings.TrimSpace(env(admission.override, ""))
		if overridden == "" {
			continue
		}
		provisioned, _ := codefly.For(ctx).WorkspaceConfiguration(WorkloadIdentityGroup, admission.key)
		if strings.TrimSpace(provisioned) == "" {
			continue
		}
		return fmt.Errorf("the %s is answered twice: %s names %q and the platform provisioned %s/%s as %q. A value this process is held to with two sources is refused rather than ranked — whichever it picked, the other is a decision somebody made that is not in force. Unset the override, or remove the provisioning",
			admission.what, admission.override, overridden, WorkloadIdentityGroup, admission.key, strings.TrimSpace(provisioned))
	}
	return nil
}

// WorkloadIdentityGroup is the workspace configuration group through which the
// platform tells this workload where its own identity material lives: the
// projected service-account token it mints its credential with, the X.509-SVID
// key pair its listener presents, and the anchor its peers are verified
// against.
//
// Paths, never material, and no exception: every value this group carries is a
// file path, and the file behind it is read by this process — the token on every
// renewal, the key pair and the anchor on every handshake, the two admission
// sets on every handshake and dial. The SDK's own value accessors would be the
// wrong tool for any of it: a file-carried configuration value is read once and
// kept for the life of the process (sdk-go file_carrier.go), which is exactly
// right for a configuration value and exactly wrong for anything the platform
// changes under a running process.
//
// The two admission sets were the exception, carried as values here and
// re-resolved through that accessor on every handshake, which looked live and
// was not: the accessor returns what the process started with, so revoking a
// caller took a restart while the code and the README both said it did not.
// Material the platform can change is a path in this group or it is a snapshot
// pretending otherwise.
const WorkloadIdentityGroup = "workload-identity"

// The keys of WorkloadIdentityGroup. Each has an explicit environment override
// below, for an operator with a projection the resolver cannot see.
const (
	WorkloadIdentityTokenFileKey       = "TOKEN_FILE"
	WorkloadIdentityCertFileKey        = "CERT_FILE"
	WorkloadIdentityKeyFileKey         = "KEY_FILE"
	WorkloadIdentityTrustBundleFileKey = "TRUST_BUNDLE_FILE"
	// WorkloadIdentityAllowedCallersFileKey names the *file* listing the
	// identities allowed to call this solution. See allowedCallersFile for why
	// it is a path and not the list: a provisioned value is fixed at process
	// start, and an admission decision that cannot narrow while the process
	// runs is a decision this listener would keep honouring after it was
	// revoked.
	WorkloadIdentityAllowedCallersFileKey = "ALLOWED_CALLERS_FILE"
	// WorkloadIdentityMintPeersFileKey and
	// WorkloadIdentityGatewayPeersFileKey name the *files* listing the
	// identities this runtime will present its credentials to, one per
	// destination. Paths, for the reason above.
	//
	// Two keys rather than one, because the mint and the gateway are two
	// parties and a single set lets each stand in for the other at the other's
	// address.
	WorkloadIdentityMintPeersFileKey    = "MINT_PEERS_FILE"
	WorkloadIdentityGatewayPeersFileKey = "GATEWAY_PEERS_FILE"
)

// The environment overrides for the paths above. Each names a file, and
// loadConfig logs which source answered for the two admission paths — an
// override that quietly outranked the platform's provisioning was the one way
// an operator could widen admission without it appearing anywhere.
const (
	ProjectedTokenFileEnvironmentVariable      = "CODEFLY__WORKLOAD_TOKEN_FILE"
	IdentityCertFileEnvironmentVariable        = "CODEFLY__WORKLOAD_IDENTITY_CERT_FILE"
	IdentityKeyFileEnvironmentVariable         = "CODEFLY__WORKLOAD_IDENTITY_KEY_FILE"
	IdentityTrustBundleFileEnvironmentVariable = "CODEFLY__WORKLOAD_IDENTITY_TRUST_BUNDLE_FILE"
	// IdentityMintPeersFileEnvironmentVariable and
	// IdentityGatewayPeersFileEnvironmentVariable override the files listing
	// the identities this runtime accepts at each destination.
	IdentityMintPeersFileEnvironmentVariable    = "CODEFLY__WORKLOAD_IDENTITY_MINT_PEERS_FILE"
	IdentityGatewayPeersFileEnvironmentVariable = "CODEFLY__WORKLOAD_IDENTITY_GATEWAY_PEERS_FILE"
	// IdentityAllowedCallersFileEnvironmentVariable overrides the file listing
	// the identities allowed to call this solution.
	IdentityAllowedCallersFileEnvironmentVariable = "CODEFLY__WORKLOAD_IDENTITY_ALLOWED_CALLERS_FILE"
)

// CredentialMintURLEnvironmentVariable is the host endpoint this runtime mints
// its execution credential at. Required: there is no default, because the
// address this runtime sends its projected service-account token to is not an
// address it may assume.
const CredentialMintURLEnvironmentVariable = "CODEFLY__CREDENTIAL_MINT_URL"

// ContractProfileEnvironmentVariable overrides the configuration profile the
// published contract is read under. Unset, it is the Codefly environment's own
// name, which is how Core resolves a profile for an environment that declares
// none (resources.Environment.ConfigurationProfileNames). A deployed
// environment therefore reads its own profile rather than the developer
// machine's — the gap codefly-dev/core#687 named and core v0.7.1 closed.
const ContractProfileEnvironmentVariable = "CODEFLY__CONTRACT_PROFILE"

// credentialMintPath is the path this package's own tests mount their fake mint
// on. It is NOT a default: nothing in loadConfig derives an address from it,
// because the host has not settled brokered-versus-direct and a guessed mint
// address is refused rather than assumed. It exists so the suite's fixtures
// agree with each other.
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
	// First, because it is the one refusal that says a decision somebody made
	// is not the one in force, and every other message below would read as
	// ordinary provisioning advice next to it.
	if c.admissionConflict != nil {
		return c.admissionConflict
	}
	if p, err := strconv.Atoi(c.port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("unresolved listen port %q: set PORT or ensure the SDK resolves this service's http endpoint", c.port)
	}
	// Both of these carry credentials: the mint presents the projected token
	// that attests which workload this process is, and the gateway carries the
	// viewer's bearer and the capability minted for them. So each has to be
	// resolved *and* has to be a destination this process can authenticate and
	// cannot be read off the wire.
	for _, required := range []struct{ name, value, override string }{
		{"gateway URL", c.gatewayURL, "GATEWAY_URL"},
		{"credential mint URL", c.mintURL, CredentialMintURLEnvironmentVariable},
	} {
		u, err := url.Parse(required.value)
		if err != nil || !u.IsAbs() || u.Host == "" {
			if c.environmentLoadErr != nil {
				return fmt.Errorf("unresolved %s %q, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
					required.name, required.value, c.environmentLoadErr)
			}
			if required.name == "credential mint URL" {
				return fmt.Errorf("no credential mint URL resolved: this runtime POSTs the projected service-account token that attests which workload it is to this address, so there is no default for it — a path assumed on the resolved gateway would be sending that attestation to an endpoint nobody published. Set %s to the endpoint this host actually serves. The fix that removes the override is the host publishing its mint as a resolvable endpoint role, which belongs to the host and the SDK rather than here",
					CredentialMintURLEnvironmentVariable)
			}
			return fmt.Errorf("unresolved %s %q: the SDK could not resolve the host endpoint and no explicit override was set", required.name, required.value)
		}
		// Plaintext is refused rather than warned about. A TLS listener
		// protects what callers send *to* this process and nothing this
		// process sends out: over http://, the mint hands this workload's
		// projected service-account token to anything on the path, and a
		// viewer's mint hands over their bearer and the capability minted for
		// them. The listener being TLS-only made the inbound hop safe and left
		// the outbound ones exactly as they were.
		if u.Scheme != "https" {
			return fmt.Errorf("%s %q is not https: it carries %s, so a plaintext hop hands them to anything on the path. Set %s to an https destination",
				required.name, required.value, credentialsCarriedOn(required.name), required.override)
		}
		// And nothing but a destination. These three were accepted, and the
		// first two were then written to the log at every boot:
		//
		//   - userinfo (https://ops:s3cr3t@mint.cell/…) is a credential in a
		//     URL, which net/http also strips from the request it sends, so it
		//     is a secret that is logged and never used;
		//   - a query (…?token=s3cr3t) is the same shape, and it travels;
		//   - a fragment is never sent at all, so a destination carrying one
		//     is not the destination somebody meant.
		//
		// A boot refusal is the right answer rather than quietly trimming
		// them: an operator who put a token in this URL believes it is doing
		// something.
		switch {
		case u.User != nil:
			return fmt.Errorf("%s carries userinfo: credentials in a URL are a secret that this runtime would log at boot and net/http would strip from the request, so it is disclosed and never used. Put the host in %s and nothing else",
				required.name, required.override)
		case u.RawQuery != "":
			return fmt.Errorf("%s carries a query string: this address is dialled, not templated, and anything secret in a query is logged by every hop that sees the URL. Put the host and path in %s and nothing else",
				required.name, required.override)
		case u.Fragment != "":
			return fmt.Errorf("%s carries a fragment: a fragment is never sent, so this is not the destination it appears to be. Set %s to the address the host actually serves",
				required.name, required.override)
		}
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
	// Said at every boot: the operator set this address by hand, because
	// nothing resolves it yet, so a 404 here is the endpoint not existing on
	// this host rather than this build being refused.
	// Redacted, always. validate() refuses userinfo and a query above, so there
	// should be nothing to hide — and a log line is the wrong place to depend
	// on a check that runs elsewhere.
	log.Printf("codefly: this execution's credential will be minted at %q, which was set explicitly through %s — no resolver produces it yet, so a 404 here means that endpoint does not exist on this host, not that this build was refused.",
		redactedURL(c.mintURL), CredentialMintURLEnvironmentVariable)
	return nil
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
	parsed.RawQuery, parsed.Fragment = "", ""
	return parsed.Redacted()
}

// credentialsCarriedOn names what a plaintext destination would disclose, so
// the refusal says why https is not a preference.
func credentialsCarriedOn(name string) string {
	if name == "credential mint URL" {
		return "the service-account token the platform projects for this workload"
	}
	return "the viewer's bearer and the capability minted on their behalf"
}

// validateSources checks the material the *selected* sources need, which is not
// the same set for every boot.
//
// A consumer that supplied an IdentitySource has said where its identity comes
// from — a mesh CA, a SPIFFE workload API — and requiring the projected file
// paths from it as well would be requiring provisioning nothing reads. The same
// goes for a credential source and the projected token. What no source changes
// is the authority identity: the principal, the mint audience and the
// projection audience are read once and frozen on every path, because the
// published contract names the principal and the listener is held to it, and a
// hook is not a way out of either.
func (s *Server) validateSources() error {
	if s.identity == nil {
		for _, path := range []struct{ name, value, override, key string }{
			{"workload identity certificate", s.cfg.identityCertFile, IdentityCertFileEnvironmentVariable, WorkloadIdentityCertFileKey},
			{"workload identity private key", s.cfg.identityKeyFile, IdentityKeyFileEnvironmentVariable, WorkloadIdentityKeyFileKey},
			{"workload identity trust anchor", s.cfg.trustBundleFile, IdentityTrustBundleFileEnvironmentVariable, WorkloadIdentityTrustBundleFileKey},
		} {
			if err := s.cfg.requirePath(path.name, path.value, path.override, path.key); err != nil {
				return err
			}
		}
	}
	if s.credential == nil {
		if err := s.cfg.requirePath("projected service-account token", s.cfg.projectedTokenPath,
			ProjectedTokenFileEnvironmentVariable, WorkloadIdentityTokenFileKey); err != nil {
			return err
		}
	}
	// Who may call is required whatever the identity source is, because it is
	// not a property of the source: the source says who this workload *is*, and
	// this says which callers it serves.
	if err := s.cfg.requirePath("allowed caller identities", s.cfg.allowedCallersFile,
		IdentityAllowedCallersFileEnvironmentVariable, WorkloadIdentityAllowedCallersFileKey); err != nil {
		return fmt.Errorf("%w — this listener verifies a caller's certificate against the cell's trust anchor, which every workload in the cell holds one from, so without this it authenticates callers and authorizes all of them, including the modules this solution consumes, which could then set their own %s and %s and drive mints carrying this workload's attestation",
			err, orgHeader, sessionHeader)
	}
	// And whom this runtime may present its credentials to, for the same
	// reason in the other direction. It is required on every path, including a
	// supplied identity source: a source says who this workload is, not which
	// destinations are the platform.
	for _, peers := range []struct{ name, value, override, key string }{
		{"credential mint peer identity", s.cfg.mintPeersFile, IdentityMintPeersFileEnvironmentVariable, WorkloadIdentityMintPeersFileKey},
		{"gateway peer identity", s.cfg.gatewayPeersFile, IdentityGatewayPeersFileEnvironmentVariable, WorkloadIdentityGatewayPeersFileKey},
	} {
		if err := s.cfg.requirePath(peers.name, peers.value, peers.override, peers.key); err != nil {
			return fmt.Errorf("%w — this runtime presents the projected service-account token, the viewer's bearer and its own credential to these destinations, and verifying their chain and hostname says only that a destination holds a certificate this cell issued, which every workload in the cell does. Each destination has its own set, so neither party can stand in for the other at the other's address",
				err)
		}
	}
	// And both files have to be readable and name somebody *now*. The per-use
	// readers refuse a handshake over an unreadable set, which is the right
	// answer while serving and the wrong first symptom at boot: a path nobody
	// provisioned would otherwise start a listener that refuses every caller
	// and a client that refuses every dial, and report it as an admission
	// failure once traffic arrived rather than as the provisioning gap it is.
	for _, set := range []struct {
		what   string
		admits func() ([]string, error)
	}{
		{"allowed callers", s.admittedCallers()},
		{"credential mint peer identity", s.admittedMint()},
		{"gateway peer identity", s.admittedGateway()},
	} {
		if _, err := set.admits(); err != nil {
			return fmt.Errorf("the provisioned %s are not usable at boot: %w", set.what, err)
		}
	}
	return nil
}

// admittedCallers resolves the identities this listener serves, for one
// handshake, failing closed.
//
// A set that resolves to nothing refuses the handshake, and so does a file that
// cannot be read. It is the same judgement peerAnchor makes about an unreadable
// trust bundle: the alternative is serving the set this process booted with,
// which is the staleness this resolution exists to remove, and an admission
// decision that cannot be resolved is not an admission decision to guess at.
func (s *Server) admittedCallers() func() ([]string, error) {
	return resolvedIdentities(s.cfg.allowedCallersFile, fmt.Sprintf(
		"whom this listener admits could not be resolved, so the handshake is refused rather than served against the set this process booted with. Provision %s/%s, or set %s",
		WorkloadIdentityGroup, WorkloadIdentityAllowedCallersFileKey, IdentityAllowedCallersFileEnvironmentVariable))
}

// admittedMint and admittedGateway are admittedCallers for each of the two
// destinations this runtime dials, one authorization set each.
func (s *Server) admittedMint() func() ([]string, error) {
	return resolvedIdentities(s.cfg.mintPeersFile, fmt.Sprintf(
		"which identity answers for the credential mint could not be resolved, and that destination receives the projected service-account token, so the dial is refused. Provision %s/%s, or set %s",
		WorkloadIdentityGroup, WorkloadIdentityMintPeersFileKey, IdentityMintPeersFileEnvironmentVariable))
}

func (s *Server) admittedGateway() func() ([]string, error) {
	return resolvedIdentities(s.cfg.gatewayPeersFile, fmt.Sprintf(
		"which identity answers for the gateway could not be resolved, and that destination receives the viewer's bearer and the capability minted for them, so the dial is refused. Provision %s/%s, or set %s",
		WorkloadIdentityGroup, WorkloadIdentityGatewayPeersFileKey, IdentityGatewayPeersFileEnvironmentVariable))
}

// admittedAt is the authorization set for one destination address, and an error
// for an address that is neither.
//
// A dial to a third address is refused rather than held to some union: this
// runtime talks to the mint and the gateway and to nothing else, so an address
// that is neither is a misbuilt client or a redirect that got through, and
// there is no set that should admit it.
func (s *Server) admittedAt(addr string) func() ([]string, error) {
	mint, gateway := dialAddress(s.cfg.mintURL), dialAddress(s.cfg.gatewayURL)
	switch addr {
	case mint:
		return s.admittedMint()
	case gateway:
		return s.admittedGateway()
	}
	return func() ([]string, error) {
		return nil, fmt.Errorf("refusing to present this workload's credentials at %s: this runtime dials the credential mint (%s) and the gateway (%s) and nothing else, so an address that is neither has no authorization set and is not a destination this runtime has one for",
			addr, mint, gateway)
	}
}

// dialAddress is the host:port a URL is dialled at, with the scheme's default
// port made explicit so it compares equal to what the dialler is handed.
//
// Host and port together, because the two destinations may well share a host
// and differ only by port — the mint has lived on the gateway's host — and a
// comparison on the host alone would then hold both to whichever set matched
// first, which is the merge this split exists to undo.
func dialAddress(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	if parsed.Port() != "" {
		return parsed.Host
	}
	if parsed.Scheme == "http" {
		return parsed.Host + ":80"
	}
	return parsed.Host + ":443"
}

// resolvedIdentities reads an admission set from its file, per call.
//
// No caching and no last-good fallback, which is the opposite of how the leaf
// this workload presents is treated: a leaf that cannot be re-read keeps
// serving, because the old leaf is this workload's own identity and refusing it
// only turns away callers who should be let in. An admission set that cannot be
// re-read has no such safe direction — the set on disk may be narrower than the
// one in memory, and that is the case this reads per handshake for.
func resolvedIdentities(path, unresolved string) func() ([]string, error) {
	return func() ([]string, error) {
		if path == "" {
			return nil, fmt.Errorf("%s", unresolved)
		}
		content, err := readAdmissionFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: reading %q: %w", unresolved, path, err)
		}
		identities, err := parsedIdentities(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", unresolved, path, err)
		}
		if len(identities) == 0 {
			return nil, fmt.Errorf("%s: %q names none", unresolved, path)
		}
		return identities, nil
	}
}

// admissionFileLimit caps an admission file.
//
// A set this runtime reads on every handshake, on every dial, and once a second
// per established connection in each direction is not a file to read without a
// bound: a 10MB one measured 9.5ms per read, which is a cost an operator can
// inflict by accident and an attacker who can write that path can inflict on
// purpose. A realistic set is a handful of SPIFFE IDs.
const admissionFileLimit = 64 << 10

// readAdmissionFile reads an admission set with a size bound.
func readAdmissionFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, admissionFileLimit+1))
	if err != nil {
		return "", err
	}
	if len(content) > admissionFileLimit {
		return "", fmt.Errorf("the file is larger than %d bytes, which is not a set of identities: this is read on every handshake, every dial, and once a second per established connection", admissionFileLimit)
	}
	return string(content), nil
}

// parsedIdentities is the admitted set a file names, and an error for a file
// this runtime will not guess at.
//
// Each entry must be a *complete* line, which is the part that matters and is
// not obvious. The previous reader split on whatever it was handed, so a file
// caught mid-write — the platform rewriting it without an atomic swap, an
// operator's `>` redirect — truncated an entry and the truncation was admitted
// as an identity of its own: ".../sa/gateway-internal" read as ".../sa/gateway"
// and let in a caller the set never named. A trailing newline is the only
// evidence a line is whole, so a final fragment is refused rather than taken.
//
// Each entry is then checked to be a SPIFFE ID, because that is what it is
// compared against and an entry that cannot match anything is a provisioning
// mistake this runtime should name at boot rather than carry silently.
func parsedIdentities(raw string) ([]string, error) {
	if strings.HasPrefix(raw, "\ufeff") {
		return nil, fmt.Errorf("the file begins with a byte-order mark, so its first entry can never match an identity")
	}
	if raw != "" && !strings.HasSuffix(raw, "\n") {
		return nil, fmt.Errorf("the file does not end in a newline, so its last line may be a fragment of one — a set caught mid-rewrite would otherwise admit a truncated identity as an identity of its own")
	}
	var identities []string
	for _, line := range strings.Split(raw, "\n") {
		if hash := strings.Index(line, "#"); hash >= 0 {
			line = line[:hash]
		}
		for _, entry := range strings.Split(line, ",") {
			trimmed := strings.TrimSpace(entry)
			if trimmed == "" {
				continue
			}
			if err := usableIdentity(trimmed); err != nil {
				return nil, err
			}
			identities = append(identities, trimmed)
		}
	}
	return identities, nil
}

// usableIdentity refuses an entry that could never match a peer, so the refusal
// names the provisioning rather than appearing later as a caller nobody admits.
func usableIdentity(entry string) error {
	for _, r := range entry {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0xfeff {
			return fmt.Errorf("the entry %q contains a control character, so it can never match an identity a peer presents", entry)
		}
	}
	parsed, err := url.Parse(entry)
	if err != nil {
		return fmt.Errorf("the entry %q is not a URI: an admitted identity is a SPIFFE ID, compared against the one URI SAN a peer's certificate carries", entry)
	}
	if parsed.Scheme != "spiffe" || parsed.Host == "" || parsed.Path == "" {
		return fmt.Errorf("the entry %q is not a SPIFFE ID (spiffe://<trust-domain>/<path>): it is compared against the one URI SAN a peer's certificate carries, so an entry of another shape admits nobody and is a provisioning mistake rather than a narrower set", entry)
	}
	return nil
}

// parsedAllowedCallers splits and trims the configured caller identities.
// A provisioned file is naturally one identity per line and a hand-written
// override is naturally comma-separated, so both separate, and a comment line
// is dropped: a set an operator cannot annotate gets annotated anyway, in a
// place nothing reads.
func parsedAllowedCallers(raw string) []string {
	var allowed []string
	for _, line := range strings.Split(raw, "\n") {
		// Comments are stripped per line and before the commas are split, so a
		// commented-out line cannot contribute its tail as an identity.
		if hash := strings.Index(line, "#"); hash >= 0 {
			line = line[:hash]
		}
		for _, id := range strings.Split(line, ",") {
			if trimmed := strings.TrimSpace(id); trimmed != "" {
				allowed = append(allowed, trimmed)
			}
		}
	}
	return allowed
}

// requirePath refuses an unresolved path, naming the override and the group the
// platform provisions it through — and saying so differently when the
// environment never loaded, because sending an operator to provision something
// that is already provisioned is the worse of the two mistakes.
func (c config) requirePath(name, value, override, key string) error {
	if value != "" {
		return nil
	}
	if c.environmentLoadErr != nil {
		return fmt.Errorf("no %s path resolved, and loading Codefly's injected environment failed first: %w — the projection may well be in place; fix the environment load before treating this as missing provisioning",
			name, c.environmentLoadErr)
	}
	return fmt.Errorf("no %s path resolved: this listener presents this workload's X.509-SVID and requires its callers to present theirs, and there is no plain-HTTP listener, so this is required. Set %s, or have the platform provision %s/%s and declare that group as a workspace-configuration dependency of this backend",
		name, override, WorkloadIdentityGroup, key)
}

// New starts a solution builder for the given manifest.
func New(manifest Manifest) *Server {
	if manifest.ExposedModule == "" {
		manifest.ExposedModule = "./Page"
	}
	if manifest.Contract == "" {
		// The solution's own id, which is what the field's documentation has
		// always promised. It used to default to a product's name — a literal
		// from one deployment, in a runtime that is supposed to know nothing
		// about any specific solution, so every solution that left the field
		// unset announced that product's capability contract to the host.
		manifest.Contract = manifest.ID
	}
	return &Server{manifest: manifest, handlers: make(map[string]RequestHandler), terminal: make(chan struct{})}
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
	if err := s.validateSources(); err != nil {
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
	// This workload's identity, resolved and held to every posture rule —
	// including that the leaf is the principal the platform provisioned —
	// before the first outbound act. Two bugs lived in the four lines this
	// replaces.
	//
	// It was conditional: `if s.credential == nil || s.identity == nil`. With
	// *both* sources supplied the client was never built, so s.outbound stayed
	// nil and every gateway call fell through to the unauthenticated transport
	// — system roots, no client certificate — which is the one posture this
	// cutover exists to remove, reached by supplying more configuration rather
	// than less. And with only Identity() supplied, the condition was true, so
	// the client read the projected files validateSources had just declared
	// unnecessary for that boot: the README's own example could not start.
	//
	// It also ran after the mint. A leaf issued for a neighbouring workload had
	// therefore already been presented to the host, with this workload's
	// projected token, by the time listen() refused it.
	identityConfig, err := s.serverIdentity()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	outbound, err := s.outboundClient(identityConfig)
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.outbound = outbound
	// The contract this solution publishes is resolved from the same
	// declaration, under the profile this process runs in, and every value it
	// requires is named in the refusal when it is absent.
	contract, err := s.resolveContract()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.contract = contract
	s.contractResolved = true
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
	mux.HandleFunc(HealthPath, s.handleHealth)
	for path, handler := range s.handlers {
		mux.HandleFunc(path, withCORS(s.wrapRequest(handler)))
	}
	mux.Handle("/assets/", http.StripPrefix("/assets/", withCORSHandler(s.assetsHandler())))
	if err := s.mountPassthrough(mux); err != nil {
		return err
	}

	watch, err := s.watchInboundTrust()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler: mux,
		// See inboundHandshakeTimeout and inboundIdleTimeout: with all of
		// these unset, a peer that never finishes its ClientHello held a
		// goroutine and a descriptor for as long as it liked.
		ReadHeaderTimeout: inboundHandshakeTimeout,
		IdleTimeout:       inboundIdleTimeout,
		// And every served connection is held to trust as it is now, not as
		// it was when the handshake happened.
		ConnState: watch,
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-s.credentialRefusedC():
		}
		srv.Close()
	}()

	log.Printf("solution %q listening on :%s (gateway=%s, profile=%s)", s.manifest.ID, s.cfg.port, redactedURL(s.cfg.gatewayURL), s.cfg.profile)
	if serveErr := srv.Serve(ln); !errors.Is(serveErr, http.ErrServerClosed) {
		return serveErr
	}
	// A terminal credential failure is reported as the reason this process
	// ended, so the orchestrator's restart is against a judgement rather than
	// an unexplained exit.
	if err := s.terminalErr.Load(); err != nil && ctx.Err() == nil {
		return fmt.Errorf("solution %q stopped serving: %w", s.manifest.ID, *err)
	}
	return nil
}

// handleHealth answers the host's probe with what this process can actually do.
//
// It was an unconditional 200, which is only right while the one thing this
// runtime needs is still true. Once the issuer has refused this execution's
// credential for good, the process can serve no module call for any viewer: a
// 200 then invites the host to keep routing to a binding that answers 503 to
// everything, and the probe is the only channel this runtime has to say
// otherwise — it does not push liveness, so it has to answer honestly.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.terminalErr.Load(); err != nil {
		// Named, not detailed: a probe is not a place to put the issuer's text.
		http.Error(w, "this execution's credential has been refused and will not be renewed; this process is ending", http.StatusServiceUnavailable)
		return
	}
	// The probe asks the credential, rather than only reporting a refusal some
	// *other* request happened to discover.
	//
	// Renewal is lazy by design — the client renews when a caller asks for the
	// credential — so a solution that serves only ViewerBearer routes, plain
	// handlers and assets never asks, and therefore never learns that the
	// issuer has stopped approving this build. It would keep answering 200 and
	// keep serving, with the refusal arriving only if some request eventually
	// needed a capability. That is the same "serves nothing, looks alive" shape
	// one layer out, and the probe is the one channel this runtime has.
	//
	// Asking is cheap and is not a heartbeat: the client holds one credential
	// and hands the same one back until its renewal point, so this is a
	// mutex and a comparison except at the renewal the credential's own expiry
	// dictates. Nothing here runs on a timer this runtime chose.
	if s.credential != nil {
		// Through credentialWithin, so the deadline is real: passing a context
		// to the SDK's client does not bound it, because what blocks is a
		// mutex held across the mint.
		if _, err := s.credentialWithin(r.Context(), healthCredentialTimeout); err != nil {
			if errors.Is(err, ErrCredentialRefused) {
				http.Error(w, "this execution's credential has been refused and will not be renewed; this process is ending", http.StatusServiceUnavailable)
				return
			}
			// Transient: the issuer cannot answer right now. Still unhealthy —
			// this process cannot act for a viewer until it can — but it is not
			// a judgement, so nothing ends.
			http.Error(w, "this execution's credential cannot currently be obtained", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
}

const routeCredentialTimeout = 500 * time.Millisecond

// healthCredentialTimeout bounds what a probe will wait for the credential, so
// a hung issuer makes the probe fail rather than parking it.
const healthCredentialTimeout = 2 * time.Second

// actingForAViewer refuses to act on a viewer's behalf while this process holds
// no credential the issuer still approves.
//
// Every route that does anything for a viewer asks this first, and that was the
// hole: the *probe* asked the credential and the routes did not. The reasoning
// is written out at handleHealth — renewal is lazy, so a solution serving only
// plain handlers and ViewerBearer routes never asks and never learns the issuer
// has stopped approving this build — and it was applied to the one caller that
// reports health rather than to the callers that act. A booted server whose
// credential had been refused kept answering 200 and kept forwarding the
// viewer's bearer to the gateway, with the credential consulted zero times.
//
// A plain handler looks like it needs no credential, which is the trap. What
// authorises this process to act for a viewer at all *is* the credential: it is
// what the host approved for this build. Forwarding a viewer's bearer under a
// credential the issuer has withdrawn is acting without authority, whether or
// not a capability is minted on the way.
//
// Cheap, and not a heartbeat: the client holds one credential and hands the
// same one back until its own renewal point, so this is a mutex and a
// comparison except at the renewal the credential's expiry dictates.
func (s *Server) actingForAViewer(ctx context.Context) error {
	if err := s.terminalErr.Load(); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialRefused, *err)
	}
	if s.credential == nil {
		return nil
	}
	_, err := s.credentialWithin(ctx, routeCredentialTimeout)
	return err
}

// credentialWithin asks for this execution's credential and never waits longer
// than d, whatever the source does.
//
// The bound has to be imposed here, because a context does not reach the thing
// that blocks. The SDK's mint client takes a sync.Mutex and holds it across the
// network mint (workcontext/mint.go, Credential), and sync.Mutex.Lock ignores
// contexts — so a caller arriving during a slow renewal waits on the lock for
// as long as the renewal takes, and the deadline it passed in bounds nothing.
// That made the two-second health deadline advisory, and it would have made
// every route's credential check park behind one slow issuer, which is a worse
// failure than the one the check was added for.
//
// The ask runs on a context detached from the caller's, deliberately: a request
// that gives up should not cancel a mint that other callers are waiting for,
// and the SDK caches the result, so the work is not wasted. It is bounded by
// its own deadline rather than by the caller's.
//
// On a timeout, the credential this process already holds decides. Refusing
// outright would turn a slow renewal — which happens while a perfectly valid
// credential is still in hand, since renewal starts inside a lead before expiry
// — into a 503 for every viewer.
func (s *Server) credentialWithin(ctx context.Context, d time.Duration) (workcontext.Credential, error) {
	type answer struct {
		credential workcontext.Credential
		err        error
	}
	answered := make(chan answer, 1)
	go func() {
		asked, cancel := context.WithTimeout(context.WithoutCancel(ctx), platformRequestTimeout)
		defer cancel()
		credential, err := s.credential.Credential(asked)
		if err == nil {
			s.credentialValidUntil.Store(credential.ExpiresAt().UnixNano())
		}
		answered <- answer{credential, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case got := <-answered:
		if got.err != nil {
			if terminalCredentialFailure(got.err) {
				// Records it, which also ends the process: the first caller to
				// discover a refused build is as good a place to learn it as
				// the probe, and better than the next one.
				s.credentialRefused(got.err)
				return got.credential, fmt.Errorf("%w: %w", ErrCredentialRefused, got.err)
			}
			return got.credential, fmt.Errorf("%w: %w", ErrCredentialUnavailable, got.err)
		}
		return got.credential, nil
	case <-timer.C:
		if until := s.credentialValidUntil.Load(); until > 0 && time.Now().UnixNano() < until {
			// A credential is in hand and has not expired. The ask continues
			// in the background and the next caller gets its result.
			return workcontext.Credential{}, nil
		}
		return workcontext.Credential{}, fmt.Errorf("%w: it did not answer within %s", ErrCredentialUnavailable, d)
	}
}

// routeCredentialTimeout bounds what a route acting for a viewer will wait for
// the credential. Short, because the answer is almost always a comparison
// against one already held, and a route is not the place to wait out a mint.

// ErrCredentialRefused and ErrCredentialUnavailable are why a route refused to
// act for a viewer: a judgement about this build, or an issuer that cannot
// answer right now. Both are 503 — this process cannot act either way — and
// they stay distinguishable because conflating them was a review blocker in
// both directions.
var (
	ErrCredentialRefused     = errors.New("this execution's credential has been refused and will not be renewed, so this process will not act for a viewer")
	ErrCredentialUnavailable = errors.New("this execution's credential cannot currently be obtained, so this process will not act for a viewer")
)

// executionCredentialSuperseded drops this process's belief that the credential
// it holds is still honoured.
//
// What it does not do is force a new one, and that is the honest limit. The
// SDK's mint client caches one credential and re-mints only once it enters its
// own renewal lead (workcontext/mint.go, dueForRenewalLocked); it exposes no
// way to invalidate what it holds. So a credential superseded *before* that
// lead keeps being handed back, and every call presenting it is refused until
// the lead arrives. The two things that would close that are a host answer that
// distinguishes "the credential you presented is superseded" from "the viewer
// lacks that authority", and a way to tell the mint client to forget what it
// cached — neither of which is this repository's to add.
//
// A renewal refused because the sealed state moved is a different case and
// already recovers: the SDK's contract for it is a refresh and a retry, this
// runtime classifies it as transient rather than terminal, and the next ask
// mints afresh.
func (s *Server) executionCredentialSuperseded() {
	s.credentialValidUntil.Store(0)
}

// credentialRefused records a judgement the issuer will not reverse.
func (s *Server) credentialRefused(err error) {
	s.terminalOnce.Do(func() {
		s.terminalErr.Store(&err)
		log.Printf("solution %q: this execution's credential was refused and will not be renewed, so this process is ending for the orchestrator to restart against the delivery as it stands: %v",
			s.manifest.ID, err)
		close(s.terminal)
	})
}

// credentialRefusedC is the channel serve waits on. Created in New, never
// lazily: a request goroutine reporting a refusal and serve reading it would
// otherwise race on the field itself.
func (s *Server) credentialRefusedC() <-chan struct{} { return s.terminal }

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

func (s *Server) wrapRequest(handler RequestHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("authorization")
		if bearer == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer"})
			return
		}
		// Before the handler, because the handler is what acts. See
		// actingForAViewer: a plain handler that mints nothing still receives a
		// gateway carrying the viewer's bearer, and sending that anywhere under
		// a credential the issuer has withdrawn is acting without authority.
		if err := s.actingForAViewer(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
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
// the next request. Bounded: a body larger than this is not worth reading to
// keep one connection.
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
	// writes, and report throttles that line.
	id     string
	report *attestationReport
	// transport is what this gateway dials with: the boot's authenticated
	// client, or nil on a gateway built outside a boot.
	transport http.RoundTripper
	// terminal reports a credential failure the issuer will not reverse, so the
	// process can stop claiming to be healthy. Nil outside a boot.
	terminal func(error)
	// superseded is called when the host refuses a mint with a conflict, which
	// is how it answers a credential sealed to state that has moved. See
	// Server.executionCredentialSuperseded.
	superseded func()
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
	gw.workload, gw.id, gw.report = s.credential, s.manifest.ID, &s.attestation
	gw.terminal, gw.superseded = s.credentialRefused, s.executionCredentialSuperseded
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

// HTTPClient returns an http.Client that injects the caller's bearer — and, on
// a gateway derived by ForModule, the viewer's Work Context — on every request.
// Satisfies connect.HTTPClient. Advanced escape hatch — prefer Unary.
func (g *Gateway) HTTPClient() *http.Client {
	transport := bearerTransport{bearer: g.bearer, base: g.roundTripper()}
	if g.delegation != nil {
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
// A gateway built by a boot carries the transport that boot configured, which
// presents this workload's identity and verifies the far end against the anchor
// the platform projected. One built outside a boot — the passthrough test seam,
// a unit test — falls back to the unauthenticated non-proxied transport, and
// that is the only place it is used: there is no path on which a *booted*
// runtime dials the platform without presenting its identity.
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

// outboundClient is the client this runtime makes platform requests with: the
// credential mint, and every call a handler's gateway issues.
//
// This is the other half of refusing a plaintext destination. An https URL says
// only that the scheme is https: without a trust anchor the connection is
// verified against whatever the image's system roots happen to contain, and
// without a client certificate the far end cannot tell this workload from
// anything else that reached it. So the client presents this workload's
// X.509-SVID and verifies the far end against the anchor the platform
// projected — the same pair and the same anchor the listener uses, which is the
// point: one identity, used in both directions.
//
// It refuses to follow redirects. net/http strips only Authorization,
// WWW-Authenticate and Cookie when a redirect crosses hosts; every other header
// — the projected token on a mint, a viewer's capability on a module read — is
// copied to the new target verbatim, and a 307/308 re-sends the body with them.
// So anything able to answer with a Location would be handed the credentials
// that prove who this workload is, and the theft would look like an ordinary
// successful request.
func (s *Server) outboundClient(identityConfig *tls.Config) (*http.Client, error) {
	// A fresh configuration per connection, so the anchor this runtime judges
	// the platform by is re-read rather than snapshotted at boot.
	//
	// Judging by a stale anchor admits whoever should be refused, which is not
	// symmetric with serving a stale leaf — the inbound argument, and it
	// applies outbound with more force, not less. The two destinations on the
	// other side of this
	// client are the mint and the gateway — they receive the projected
	// service-account token, the viewer's bearer and this workload's own
	// credential — so a root removed from the bundle because it was compromised
	// kept authenticating exactly the parties that are handed everything.
	//
	// Reloading per connection is the whole story only if connections do not
	// outlive the reload, so established connections are re-verified too (see
	// below).
	//
	// What is *not* rebuilt per connection is this workload's own leaf source.
	// Building a whole new SDK reloader per dial, and again per recheck of
	// every connection, looks like "nothing is snapshotted" and is a
	// regression: NewCertificateReloader loads
	// eagerly and returns the error, where a long-lived reloader swallows a
	// failed re-read and keeps serving the last good pair. So a cert rotated
	// non-atomically — the certificate written, the key a moment behind —
	// failed every new dial, and failed every recheck, which closed
	// established connections whose peers were still perfectly trusted. A
	// half-written copy of this workload's own key is not a judgement about
	// the peer, and the two must not share a failure path.
	leaf, err := s.outboundLeaf(identityConfig)
	if err != nil {
		return nil, err
	}
	trust := s.peerTrustAnchor(identityConfig)
	// Per destination, not per "platform": the authorization set is chosen by
	// the address being dialled, so the mint's identity is not accepted at the
	// gateway's address or the other way round, and a third address has no set
	// and is refused.
	newConfig := func(addr string) (*tls.Config, error) {
		anchor, err := trust()
		if err != nil {
			return nil, err
		}
		config := &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              anchor,
			GetClientCertificate: leaf,
		}
		// Held to the frozen principal at presentation, and pointed at the one
		// identity allowed to answer at this address. Both apply to a
		// consumer's source and to the projected pair: one of the two paths
		// carrying a check is not the check.
		if err := holdPresentedCertificate(config, s.principal); err != nil {
			return nil, err
		}
		admitOnlyPlatform(config, s.admittedAt(addr))
		return config, nil
	}
	// Refused at boot rather than at the first dial: a configuration this
	// runtime cannot build is a boot failure, not a mint that fails later.
	if _, err := newConfig(dialAddress(s.cfg.gatewayURL)); err != nil {
		return nil, err
	}

	transport := newPlatformTransport()
	// No TLSClientConfig: every connection builds its own below, and leaving a
	// snapshot here would be the bug this function exists to avoid.
	transport.TLSClientConfig = nil
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		config, err := newConfig(addr)
		if err != nil {
			return nil, err
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		config = config.Clone()
		config.ServerName = host
		raw, err := (&net.Dialer{Timeout: platformRequestTimeout}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		// The handshake carries its own deadline, independent of whatever the
		// caller's context says.
		//
		// A custom DialTLSContext takes net/http out of the handshake entirely:
		// it calls customDialTLS and never reaches addTLS, so
		// Transport.TLSHandshakeTimeout — inherited as 10s from
		// DefaultTransport — silently does nothing, and the only bound left is
		// the request context's. That is adequate for an ordinary request and
		// wrong exactly where it matters: Gateway.HTTPClient carries streams
		// and therefore sets no client timeout on purpose, so a dial made for
		// a stream was bounded by the method's declared MaxStreamDuration (up
		// to thirty minutes) or by nothing at all. A handshake is not a
		// stream: it completes in milliseconds or the peer is not answering.
		bound := s.handshakeTimeout
		if bound == 0 {
			bound = platformHandshakeTimeout
		}
		handshake, cancelHandshake := context.WithTimeout(ctx, bound)
		defer cancelHandshake()
		conn := tls.Client(raw, config)
		if err := conn.HandshakeContext(handshake); err != nil {
			_ = raw.Close()
			return nil, err
		}
		// Watched on the two inputs that are a judgement about the peer — the
		// anchor and the admitted set — and on nothing else.
		return watchOutboundTrust(conn, host, trust, s.admittedAt(addr)), nil
	}
	// Pool hygiene, not the trust bound: a connection nothing sends on is
	// dropped rather than held open indefinitely. What bounds the trust
	// decision is the recheck above, because an inactivity timeout cannot.
	transport.IdleConnTimeout = outboundTrustReloadBound
	return &http.Client{
		Timeout:       platformRequestTimeout,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// outboundLeaf is the certificate this runtime presents to the platform,
// resolved once and re-read by whatever produces it.
//
// Once, because the thing that keeps a rotated leaf presented is the reloader's
// own re-read, not a new reloader: the SDK's swallows a failed or half-written
// re-read and keeps serving the last good pair (sdk-go tls.go, refresh), which
// is the property that makes a rotation invisible to a caller. Building a new
// one per dial threw exactly that away, because the constructor loads eagerly
// and reports the error instead.
func (s *Server) outboundLeaf(identityConfig *tls.Config) (func(*tls.CertificateRequestInfo) (*tls.Certificate, error), error) {
	if s.identity != nil {
		// A consumer's source: the identity it returned, in both directions,
		// rather than projected files it never said it uses. Its own callback
		// is what gets asked, so a source that rotates is followed.
		client, err := clientTLSFrom(s.identity, identityConfig)
		if err != nil {
			return nil, fmt.Errorf("configure this workload's outbound identity from the supplied identity source: %w", err)
		}
		if client.GetClientCertificate != nil {
			return client.GetClientCertificate, nil
		}
		pairs := client.Certificates
		return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if len(pairs) == 0 {
				return nil, fmt.Errorf("the identity source produces no certificate this runtime can present to the platform")
			}
			return &pairs[0], nil
		}, nil
	}
	reloader, err := codefly.NewCertificateReloader(s.cfg.identityCertFile, s.cfg.identityKeyFile)
	if err != nil {
		return nil, fmt.Errorf("configure this workload's outbound identity from %q/%q: %w — the same pair the listener presents is what names this workload to the platform it calls",
			s.cfg.identityCertFile, s.cfg.identityKeyFile, err)
	}
	return reloader.GetClientCertificate, nil
}

// outboundTrustReloadBound is how long a connection nobody is using is kept in
// the pool. Pool hygiene, nothing more.
//
// It used to be described as the bound on outbound trust staleness, and it was
// not one: an inactivity timeout bounds only a connection that goes inactive,
// so a connection carrying traffic was never dropped and the documented window
// held for a quiet process only. What bounds the trust decision is
// outboundTrustRecheckInterval below.
const outboundTrustReloadBound = 30 * time.Second

// outboundTrustRecheckInterval bounds how long an established platform
// connection may outlive the trust that authenticated it.
//
// It is the number the reload bound above could not deliver on its own. Peer
// trust is re-read on every dial, and that was documented as a 30-second
// window on the strength of IdleConnTimeout — but an *inactivity* timeout
// bounds only a connection nobody is using. A connection carrying a request
// every 100ms never becomes idle, and one was demonstrated still answering 31
// seconds after the server's trust root was removed, over a single handshake:
// traffic kept the connection, and the trust decision behind it, alive for as
// long as it kept arriving. A stream is the same shape by construction, held
// open for as long as its declared duration allows (up to
// MaxStreamDurationLimit).
//
// A second, not the idle bound's thirty: the recheck is a file read and a chain
// verification against a chain already in hand, a few hundred microseconds on a
// handful of platform connections, so the window is set by what the guarantee
// should be rather than by what the work costs. It is also what makes the
// busy-connection case testable in about a second instead of half a minute.
const outboundTrustRecheckInterval = time.Second

// watchOutboundTrust re-verifies an established connection's peer against
// current trust, and closes the connection when it stops verifying.
//
// Re-verifying rather than imposing a maximum connection age, which was the
// other way to bound this. A maximum age cuts whatever is in flight when it
// expires, and a declared 30-minute stream over a peer that is still perfectly
// trusted would be cut every bound — the runtime would be ending conforming
// streams to answer a question it can answer without ending them. The chain the
// peer presented is already in hand, so the anchor and the allowed-peer set can
// be re-read and applied to it: a connection whose peer still verifies is left
// alone, and one whose peer no longer does is closed, busy or idle, stream or
// request.
//
// A closed connection surfaces as a failed request or a cut stream, which is
// the intended outcome: the alternative is continuing to present this
// workload's credentials — and the viewer's — to a destination this cell has
// stopped vouching for.
func watchOutboundTrust(conn *tls.Conn, host string, trust func() (*x509.CertPool, error), peers func() ([]string, error)) net.Conn {
	watched := &recheckedConn{Conn: conn, done: make(chan struct{})}
	go func() {
		ticker := time.NewTicker(outboundTrustRecheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watched.done:
				return
			case <-ticker.C:
				if err := peerStillTrusted(conn.ConnectionState(), host, trust, peers); err != nil {
					_ = watched.Close()
					return
				}
			}
		}
	}()
	return watched
}

// recheckedConn is the connection the transport holds, so the recheck stops
// when net/http drops it.
type recheckedConn struct {
	net.Conn
	stop sync.Once
	done chan struct{}
}

func (c *recheckedConn) Close() error {
	c.stop.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// peerStillTrusted holds the chain this connection was authenticated by to
// trust as it is now: the current anchor, the current allowed-peer set, and the
// current time, which is also how a peer certificate that expired mid-stream
// stops being accepted.
// It takes the anchor and the admitted set, not a whole configuration to
// rebuild: a recheck that also resolved this workload's own leaf would close a
// trusted connection over a half-written copy of this process's own key, which
// is not a statement about the peer at all.
func peerStillTrusted(state tls.ConnectionState, host string, trust func() (*x509.CertPool, error), peers func() ([]string, error)) error {
	anchor, err := trust()
	if err != nil {
		return err
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("the established platform connection presents no peer certificate to re-verify")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         anchor,
		Intermediates: intermediates,
		DNSName:       host,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("the platform destination this connection was authenticated against no longer verifies: %w", err)
	}
	// And the same identity check a dial makes, since the allowed-peer set is
	// read per dial and a connection older than a change to it would otherwise
	// keep a de-authorised destination.
	admitted, err := peers()
	if err != nil {
		return err
	}
	identity, err := oneURIIdentity(state, "platform destination")
	if err != nil {
		return err
	}
	if !slices.Contains(admitted, identity) {
		return fmt.Errorf("the established connection's destination %q is no longer one this runtime presents its credentials to", identity)
	}
	return nil
}

// platformHandshakeTimeout bounds one outbound TLS handshake, on its own,
// because the custom dialler means nothing else does. It is deliberately not
// derived from platformRequestTimeout: a request may legitimately be long (a
// declared stream), and a handshake never is.
const platformHandshakeTimeout = 10 * time.Second

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
	return g.contexts.resolve(ctx, g.delegation.key, func(ctx context.Context) (string, time.Time, error) {
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

func (g *Gateway) mint(ctx context.Context, ask startTaskRequest) (string, time.Time, error) {
	body, err := json.Marshal(ask)
	if err != nil {
		return "", time.Time{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, workContextMintTimeout)
	defer cancel()
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, g.baseURL+workContextStartTaskProcedure, bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	post.Header.Set("content-type", "application/json")
	// The viewer's bearer says on whose behalf; this execution's credential
	// says which module is asking. The work-context header is free on this
	// request — the capability being minted is what the answer carries, and the
	// viewer has none yet — so attesting here collides with nothing the module
	// call later presents.
	if err := attestWorkloadReporting(ctx, g.workload, g.report, post, g.id, g.terminal); err != nil {
		return "", time.Time{}, err
	}
	resp, err := g.bearerClient().Do(post)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("work context mint for %q: %w", ask.Audience, err)
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
		// A conflict is how a credential sealed to state that has moved is
		// refused. It is NOT read as a judgement about this build, and not as
		// proof that this workload's credential specifically is the stale part
		// — the host does not distinguish that from a viewer's authority in
		// this answer, and inventing the distinction would be guessing at
		// somebody else's protocol. What it does is drop this process's
		// assumption that the credential it holds is still honoured, so the
		// next route asks the source instead of proceeding on a cached belief.
		if resp.StatusCode == http.StatusConflict && g.superseded != nil {
			g.superseded()
		}
		return "", time.Time{}, &WorkContextRefusal{
			Audience: ask.Audience, StatusCode: resp.StatusCode, Code: refusal.Code, Message: refusal.Message,
		}
	}
	var issued struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expiresAt"`
		WorkContextPrincipals
	}
	if err := json.NewDecoder(resp.Body).Decode(&issued); err != nil {
		return "", time.Time{}, fmt.Errorf("work context mint for %q returned invalid json: %w", ask.Audience, err)
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
	minted map[string]cachedCapability
	// minting holds the mint in flight for an ask, so concurrent asks for the
	// same one wait on it instead of each running their own. A handler that
	// fans out would otherwise spend one audited mint per goroutine for a
	// capability they all share.
	minting map[string]*pendingMint
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
	if err == nil {
		c.minted[key] = cachedCapability{token: token, reuseUntil: reuseUntil}
	}
	c.mu.Unlock()
	close(inflight.done)
	return token, err
}

// supersede drops the capability held for one ask — the one that was refused,
// and only if it is still the one held — so the next call mints instead of
// presenting it again.
//
// It is the other half of classifying a refusal as ErrRevoked. That sentinel
// means the capability was sound when it was minted and the state moved under
// it — an installation revision, a principal's epoch, a build incarnation, a
// binding — and the holder's answer is to mint again. Classifying the error and
// then keeping the capability until its *time* ran out would answer every call
// in that window with the same refusal: the cache reused a credential the
// issuer had already stopped honouring, and a caller that re-asked got it back.
//
// The presented token is what makes this conditional, and deleting by key alone
// was a defect a concurrent pair of calls reaches without anything unusual: two
// requests present carrier-1, the first refusal evicts it, a third call mints
// carrier-2, and then the *second* late refusal — still about carrier-1 —
// deleted carrier-2, costing a third audited mint and discarding a capability
// nothing had refused. Comparing the token needs no generation counter: the
// token is the generation.
func (c *workContextCache) supersede(key, presented string) {
	c.mu.Lock()
	if issued, ok := c.minted[key]; ok && issued.token == presented {
		delete(c.minted, key)
	}
	c.mu.Unlock()
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
		return nil, err
	}
	if err := workcontext.Attach(r, token); err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(r)
	if err == nil && supersededCapability(resp) {
		// The far end says the capability it was shown is sealed to state that
		// has moved. Dropping it here is what makes the next call mint instead
		// of presenting the same one until its clock ran out: a capability the
		// issuer has stopped honouring is not a capability to reuse, however
		// much of its validity window is left.
		t.acting.contexts.supersede(t.acting.delegation.key, token)
	}
	return resp, err
}

// supersededCapability reads a far end saying the capability presented is
// sealed to state it has moved past.
//
// The signal is the status and the installation headers the carrier puts beside
// a capability, which is all a caller gets: the far end verifies, this runtime
// does not, so what reaches here is an HTTP refusal and not a sentinel. A 409
// is what the issuer answers for a revision that has moved — distinct from the
// 401 of a capability that never verified and the 403 of authority the viewer
// does not hold, neither of which another mint would fix.
func supersededCapability(resp *http.Response) bool {
	return resp.StatusCode == http.StatusConflict &&
		resp.Header.Get(workcontext.InstallationIDHeaderName) != ""
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
