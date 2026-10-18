# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns configuration
resolution, installation-scoped workload credentials, a plain-HTTP listener on the port
Codefly resolves, CORS, Module Federation asset serving, the capability
handshake, the manifest served from the declared frontend file, the published
authority contract, and the gateway client each handler uses to read composed
modules on the viewer's behalf.

A component author writes a manifest, optionally embeds a frontend, and
writes one handler:

```go
//go:embed solution.frontend.codefly.yaml
var frontend []byte

solution.New(solution.Manifest{ID: "my-solution", Frontend: frontend}).
    Handle("/thing", func(ctx context.Context, gw *solution.Gateway) (any, error) {
        resp, err := solution.Unary[Req, Resp](ctx, gw, "/pkg.Service/Method", &Req{})
        return resp, err
    }).
    Serve()
```

The gateway URL, the caller's bearer, and the wire protocol are hidden. What
the host lists the solution under — title, nav order, exposed module, host
contract, dashboard, surfaces — lives in
[`solution.frontend.codefly.yaml`](#the-declared-frontend) beside the backend's
`service.codefly.yaml`, which the CLI delivers in the presence document and
this runtime serves its manifest from.

## A runtime does not register itself

**If you are upgrading from a runtime that did, read this first.** Nothing
bridges the two models, and the cutover is deliberate:

- An **old runtime against a new host** gets `404` on the endpoints it
  registers with — they are deleted, in the same cutover, by design. It will
  log a failed registration forever and the host will never learn of it. It
  must be redeployed on this runtime. There is no compatibility mode, no
  fallback credential, and no version of the host that serves both.
- A **new runtime against an old host** registers nothing, because it has
  nothing to register with, and mints nothing, because the old host serves no
  mint endpoint: actual module work fails when it asks for authority. Boot and
  health do not contact the broker.

What changed, and why. A solution used to become present by announcing itself:
two self-registrations — the manifest to the host frontend, the dialable
upstream to the gateway — on a 15s heartbeat, each beat burning a single-use
credential the issuer audited as a mint. A solution that had not changed in a
week announced itself roughly 11,500 times a day, the audit log recorded every
one, and presence came from a process being up, which means a process could
claim it.

Presence is **delivered** now. A signed presence document declares which
solution runs on which host, at which generation and build, under which
workload identity; the host reconciles towards it. Authority is delivered the
same way, by a signed document bound to one approved build. This runtime acquires workload authority only when an operation needs it,
selecting the organisation and installation from the host-stamped request.
Boot, health, route entry and install acknowledgement never mint. Health is **answered**,
never pushed: the host probes the destination its own presence document names,
and nothing this process answers can make it present.

The runtime enforces these boundaries:

| | |
|---|---|
| The listener is plain HTTP on the resolved port | the cell's mesh carries transport security and destination identity; this process presents no identity of its own and verifies no caller — see [Plain HTTP inside the cell](#plain-http-inside-the-cell) |
| Credentials are acquired for actual module work | each organisation/installation has independent acquisition, expiry and refusal state — see [One credential per execution](#one-credential-per-execution) |
| The authority-bearing values are read once and frozen | the credential is sealed to the values it was minted under, so a value that drifts is an error, never a reload |
| The contract is published, and the declaration is held to it | an ask outside its declared ceiling fails the boot — see [The published contract](#the-published-contract) |

Execution minting uses `saas-sdk-go/moduleauthority.MintModuleWorkContext`.
The host-owned SDK encodes the broker request, parses its bounded answer and
classifies its refusals. This runtime supplies its admitted, origin-pinned
transport and bounded projection read; it retains deadline, single-flight,
seal and renewal policy. The broker expiry may shorten the signed expiry.
The request is `POST /modules/_work-context` on the gateway's **workload**
endpoint — the one origin this runtime resolves, which serves the gateway's
whole handler — with `{"prefix":"<Manifest.ID>","organization_id":"<stamped organisation>"}`,
`Authorization: Bearer <projected token>`, and `X-Codefly-Internal-Token`. The
prefix is the declared solution ID, separate from the frozen SPIFFE principal.

Nothing about where this runtime serves or what its frontend declares is
reported with the mint. Both used to be: `upstream`, an https origin the
gateway dialled, and `manifest`, the frontend manifest this runtime served.
They are deleted, not fenced. The gateway resolves this solution's address from
the delivered presence document's endpoints, through the SDK, from the carrier
the CLI hands it — as it already did for modules — and the frontend travels in
the same document, read by the CLI from the file this runtime embeds. A
process cannot declare what the composition did not.

The install step runs under the capability carried by the host. It can acknowledge
before any workload credential exists, and acknowledgement triggers no mint.
The host activates consent afterwards; a later module operation acquires against
that live consent. HTTP `412` means a required precondition is unmet; it does not
uniquely mean that the solution is installed nowhere.

The answer carries `token`, `expiresAt`,
`principalId`, and `tenant`. Core alone reads the returned capability, through
its structural `Decode` (named `Inspect` before core v0.15); the runtime does not
implement a signed encoding or verify an issuer's authority, and that read
checks no signature.

`WorkContextRefusal.Code` and `.Message` have been removed (breaking API change).
Consumers should inspect `.StatusCode` or unwrap to `GatewayError`. Broker bodies,
headers, redirect locations and raw transport diagnostics are not returned.
A viewer request retains a 401/403 for the same mint ask and never re-mints it.

The CLI projects the service-account token read-only at
`/var/run/secrets/codefly/token`, for audience `accounts`, with lifetime at most
600 seconds. That path is the boot default; the existing path configuration is
still available. Token reads are bounded to 64 KiB and repeated for every mint;
missing, empty, unreadable or oversized files fail closed before a request.

## Native listener isolation

On a local native run the runtime binds the loopback host and port of its own
SDK-resolved `http` endpoint. `PORT` can change the port, but cannot broaden the
listener to other interfaces. An absent or non-loopback native endpoint fails
configuration validation. The CLI supplies the endpoint automatically; there is
no separate host override to copy into each component.

Container and Kubernetes processes retain their container-wide listener, where
the platform owns network admission. A local environment name alone does not
turn a container listener into a loopback listener. Production admission still
requires the declared mesh boundary; this change does not qualify that boundary.

## Handler errors

Return `ClientError` for an explicitly public validation message. Connect errors
returned by `Unary` retain actionable statuses: authentication 401, permission
403, missing resource 404, invalid input 400, conflict 409, precondition 412,
quota 429, unavailable 503 and deadline 504. Other RPC failures return 502.
Only generic status text reaches the browser. Mint failures also discard upstream
diagnostics before reaching handlers or logs. No request is retried or replayed.

REST adapters can return `&solution.GatewayError{StatusCode: resp.StatusCode}`
after a non-success response through the gateway. The runtime preserves 4xx,
503 and 504; unexpected statuses and other server failures become 502. This
error carries no raw body, URL or headers. Work Context mint refusals use this
same path. Untyped errors retain the existing 502/public-error-string behavior,
so handlers must not put private details in them. Consumers using an older runtime
or flattening failures into strings must adopt these typed errors to benefit.

## Install step

`Server.OnInstall(func(context.Context, Installation) error)` declares an
optional install step and returns the server for chaining. `Installation`
contains `ID`, `OrganizationID`, `Revision` and the granted `Scope` (`[]Scope`).
`POST /_codefly/installations` accepts a JSON object with `installation_id`,
`organization_id`, a positive `revision`, and `scope` (entries use
`resourceKind`, `actions`, and `resourceIds`); unknown fields and bodies over
64 KiB return 400.

The route is served on the one listener, which the cell's mesh admits only
from the gateway's principal; the runtime requires
exactly one structurally valid Work Context via the SDK's `FromHeaders`
(including its installation carriers), carries it to the step through
`ViewerFromContext(ctx)`, and leaves verification to the host on every outgoing
call.
Missing or malformed carriers return 401 before the step runs. Use the returned
gateway's `HTTPClient` or `Unary` directly to carry that context on outgoing
calls; `ForModule` is for viewer-driven mints. The bearer is never logged or
echoed. Success, including when no step is registered, returns 204.

Return `RefuseInstall("public reason")` for an intentional refusal: it wraps
`ErrInstallRefused` and retains at most 256 printable ASCII bytes. Wrapping
diagnostics are never included in the public reason. Refusals return 409 with
`{"reason":"..."}`; other errors return 503 with only `installation step failed`.
A bare or wrapped `ErrInstallRefused` without a
`RefuseInstall` reason receives `installation refused`.

Concurrent duplicates wait for the first call. An acknowledgement (204) is
answered from memory for the most recent 1024 installation revisions; a 409 or
a 503 is not remembered, so the host's retry — or an administrator's Retry
after fixing the cause — runs the step again, and at most
64 steps run at once (past that the call is 503 and the host retries). The step
must therefore converge: it may run again for an installation it already set
up, after a retry, an eviction or a restart.

## Configuration

On boot `Serve` calls `codefly.Init(ctx)`, which loads Codefly's injected
carriers and pins the module this process belongs to from `CODEFLY__MODULE`.
Every Codefly-managed flow sets that variable; the SDK (v0.3.1 and later)
resolves no endpoint for a process it has not pinned, so a boot that names no
module — or a different one from the module the process was first pinned to —
is refused naming `CODEFLY__MODULE`, whether or not every address below was
overridden. Then `loadConfig` resolves every address, port, and path through the codefly Go SDK
(`github.com/codefly-dev/sdk-go`), falling back to the local native workspace
map when not running under the runtime. Most values have an explicit env
override for an operator with a deployment the resolver cannot see; the
SDK-resolved value is the default.

The two MCP values have none, because a Codefly composition cannot set a bare
environment variable on a service: every value a service receives is either an
endpoint the SDK resolves or a **declared configuration** the render projects.
Their override is therefore a value in the `mcp` workspace-configuration group,
resolved through the SDK — see [The resource
identifier and the issuer](#the-resource-identifier-and-the-issuer).

| What | SDK resolution | Env override (default) |
|---|---|---|
| Own listen port | `codefly.For(ctx).Endpoint("http").NetworkInstance()` — the Codefly-assigned port, not a fixed default | `PORT` |
| Gateway URL (auth-gateway `workload`) | resolved by role — the single module owning the `auth-gateway` `workload`/`http` endpoint, discovered from the injected carriers (or the workspace, run locally, where core's endpoint visibility applies: an endpoint private to the host's module is refused, not resolved, for a solution in another module). The workload endpoint serves the gateway's whole handler, the mint included; the public `rest` endpoint does not resolve it. Held to the SDK's transport rule: `https` anywhere; `http` only to a loopback host on a local run, or to an in-cluster Service address (`<svc>.<ns>.svc[.<domain>]`) when the composition asserts `internal-transport/mesh-protected=true` | `GATEWAY_URL` |
| Credential mint URL | the host's published broker route, `/modules/_work-context`, on the resolved gateway. Derived, with no override: the gateway's workload endpoint serves it, and a second address would be a second destination for the projected service-account token. A 404 there means the host does not serve its gateway's full handler on that endpoint, which is terminal | — |
| Mesh assertion | `codefly.For(ctx).WorkspaceValueIfSet("internal-transport", "mesh-protected")` — read once at boot and handed to the SDK's rule above; exactly `true` asserts that every in-cluster hop is carried by a mutually authenticated mesh, unset or `false` keeps plaintext refused, any other value is a boot refusal. The same setting the composed modules apply to their own gateway value | — (declared configuration) |
| Broker perimeter credential | `codefly.For(ctx).WorkspaceSecret("module-authority", "INTERNAL_TOKEN")`, required at boot for authority-consuming declarations. Sent only to the execution broker as `X-Codefly-Internal-Token`; it does not replace the projected token | — (declared workspace secret, no legacy env fallback) |
| Projected service-account token | a **path**, re-read at every mint; `/var/run/secrets/codefly/token`, the CLI projection, which every Codefly-managed deployment mounts | `CODEFLY__WORKLOAD_TOKEN_FILE` |
| Principal this workload runs as | `module-authority`/`PRINCIPAL`, read once and frozen | — |
| Audience it mints against | `module-authority`/`AUDIENCE`, read once and frozen | — |
| Audience of its own projected token | `module-authority`/`PROJECTION_AUDIENCE`, required to be `accounts`, read once and frozen | — |
| Contract profile | the Codefly environment's own name, which is how Core resolves a profile for an environment that declares none | `CODEFLY__CONTRACT_PROFILE` |
| MF assets | `Manifest.Assets` when set (see below), else the `../fe-remote/dist` directory | `ASSETS_DIR` (directory only) |
| Host issuer (MCP) | `codefly.For(ctx).WorkspaceConfiguration("mcp", "issuer-url")` — the declared value the composition supplies; without one, the resolved host frontend origin (see [Exposing an MCP server](#exposing-an-mcp-server)). Checked at boot only when `ServeMCP` is declared | — (declared configuration, no env override) |
| Public MCP URL | **declared** (`mcp/public-url`) in a deployed runtime context, where a derived value is refused: the derivation encodes the route the *host* serves this solution on. Locally, derived from `<PUBLIC_URL>/solutions/<id>/mcp`. Overridden by `codefly.For(ctx).WorkspaceConfiguration("mcp", "public-url")` (must end in `/mcp`). With neither, the resource identifier is reconstructed per request from `x-forwarded-proto` / `x-forwarded-host` / `x-forwarded-prefix` | — (declared configuration, no env override) |

The projected token is a **path, never a value**, because the projection is
rotated under the running process and a token read once at boot stops verifying
long before the process stops running. It is the one file this process reads
for itself; everything else is a configuration value the SDK resolves, fixed at
process start, which is right for a configuration value.

The three `module-authority` values are read through the SDK's authority reader
and **frozen**: the credential this process holds is sealed to the values it was
minted under, so a value that resolves differently later is an error and not a
reload. They are rechecked before every renewal, which is the one moment a
drifted value would otherwise be laundered into a credential nobody approved.

Every unresolved value is refused at boot, naming the value and the provisioning
path that fixes it — including the difference between "the SDK resolved nothing"
and "loading the injected environment failed first", because one generic message
sent an operator to inspect endpoint resolution over a variable they had broken
themselves.

`PUBLIC_URL` survived the cutover with one consumer. It fed the manifest
registration, where building an absolute URL from it was wrong — the route a
browser reaches this solution through is the host's to resolve — and the
manifest is a path now. The MCP resource identifier an agent client binds its
token to does need a public origin, and derives from it when no `mcp/public-url`
is declared. Whether a runtime should derive the host's `/solutions/<id>` route
even for that is an open follow-up.

**Removed with the registrations they fed**: `SELF_UPSTREAM`, `HOST_REGISTER_URL`, `GATEWAY_REGISTER_URL`,
`GATEWAY_MODULE_REGISTER_URL`, `GATEWAY_MODULE_REGISTRATION_TOKEN_URL`,
`GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL`, `CODEFLY_INTERNAL_TOKEN`,
and `CODEFLY__SOLUTION_REGISTRATION_INTERVAL`. Setting any of them now does
nothing.

**Removed with the in-cell plain-HTTP cutover**: `CODEFLY__CREDENTIAL_MINT_URL`
(the mint is the published route on the resolved gateway), the whole
`workload-identity` workspace-configuration group and its overrides
`CODEFLY__WORKLOAD_IDENTITY_CERT_FILE`, `_KEY_FILE`, `_TRUST_BUNDLE_FILE`,
`_ALLOWED_CALLERS_FILE`, `_MINT_PEERS_FILE` and `_GATEWAY_PEERS_FILE` (no
workload serves or presents an X.509-SVID, and no peer file admits anybody —
the mesh does), and the `CODEFLY__SELF_ENDPOINT__…` carrier as an input (the
advertised origin was reported with the mint, and nothing is reported). The
projected token's `CODEFLY__WORKLOAD_TOKEN_FILE` override stays; its group does
not. `Server.Identity`, `IdentitySource` and `PeerAnchorSource` are gone from
the API with the listener they configured.

`CODEFLY_HOST_FRONTEND` is **not** in that list, and this said it was. It went
with the registrations and then came back for one consumer, the same way
`PUBLIC_URL` did: it names the host's frontend service, whose resolved URL is
the fallback the MCP issuer identifier is derived from when no `mcp/issuer-url`
is declared (`resolveMCPIssuer`). It is read in `loadConfig` like every other
value here. Nothing reads the legacy `CODEFLY_INTERNAL_TOKEN` or a per-solution registration
secret. The broker perimeter token comes only from its declared workspace secret; the credential this runtime
presents attests which workload it is, and there is no fallback to one that
attests nothing.

The host it plugs into is named by Codefly-convention **service roles**, not by
its workspace module name: the runtime discovers the single module that owns the
gateway role — from the injected endpoint carriers when deployed, or the
workspace on disk when run locally — so a solution composing the host under any
module name resolves identically (codefly-dev/core#382).
The role is overridable: `CODEFLY_HOST_GATEWAY` (default `auth-gateway`). There
is no fallback to the pre-v0.0.49 `auth-sidecar` role: a composition exposing
only that one is a composition to re-render, and an unresolved current gateway
silently selecting the service that used to answer the deleted registration
endpoints is worse than a boot that fails naming the role. `CODEFLY_HOST_MODULE` is
empty by default and only needs setting to disambiguate a composition where
**more than one** module exposes the same role — otherwise an ambiguous match
resolves to nothing and the runtime fails loud at boot rather than picking a host
arbitrarily. Concrete addresses always come from the SDK.

## Plain HTTP inside the cell

Past the host's auth gateway, every hop inside a cell is plain HTTP, and the
cell's mesh — istio ambient: ztunnel mTLS, the workload's identity being its
ServiceAccount's SPIFFE ID — carries transport security and destination
identity. TLS ends at the edge. So this listener is plain TCP on the port
Codefly resolved, presents no certificate and verifies no caller: the mesh
admits the solution's port only from the gateway's principal, and a listener
that re-decided either would be a second copy of a decision the cell makes for
every workload. The SPIFFE ID a presence document names for this workload is
that mesh principal, not an SVID this process presents.

This reverses what the previous generation did. It served TLS 1.3 under an
X.509-SVID the platform projected, required and verified its callers'
certificates against a projected anchor, admitted them by a provisioned
`ALLOWED_CALLERS_FILE`, held two more provisioned sets per outbound
destination, re-verified every established connection once a second in both
directions, and refused session resumption, `GetConfigForClient` answers below
the posture, and a consumer `IdentitySource` that fabricated its anchor. All of
it is deleted, not fenced — `identity.go`, its tests, the peer files and the
SVID loading — because every one of those checks was this process re-deciding
what the mesh decides, and a process that decides it twice has two answers.

What this process still decides is what a caller may do once admitted, and
where its own credentials may travel:

- **The stamped identity headers are the viewer.** `x-org-id`, `x-session-id`
  and `x-codefly-installation-id` are read as the gateway stamped them from
  verified claims; a request reaching this port came through the gateway, or
  the mesh would not have carried it.
- **A plaintext destination is admitted only where the mesh is.** The gateway
  URL — and the mint derived on it — is held to the SDK's one transport rule,
  `workcontext.AdmitEndpoint`, the same rule the composed modules apply to
  their own gateway value: `https` to any host; `http` to a loopback host on a
  local run, or to an in-cluster Service address
  (`<svc>.<ns>.svc[.<domain>]`) when the composition asserts
  `internal-transport/mesh-protected=true`; anything else is a boot refusal
  naming the rule. The assertion is read once, in `loadConfig`, and answered
  from that snapshot wherever the rule asks — at validation and inside every
  mint — because every environment read sits in `loadConfig`'s call tree and a
  configuration value is fixed at process start anyway. Only the literal
  `true` asserts it; a misspelled assertion is refused rather than read as
  either answer.
- **A credential-bearing URL carries a destination and nothing else.**
  Userinfo, a query and a fragment are refused at boot by the same rule, and
  the boot log redacts the URL regardless, because a log line is the wrong
  place to depend on a check that runs elsewhere.
- **No credential-bearing request follows a redirect, and none leaves the
  gateway's own origin.** Go copies a request's headers onto a redirected one
  and strips only `Authorization`, `WWW-Authenticate` and `Cookie`; a 307
  re-sends the body; and this runtime sets the bearer per round trip. So a
  single `307 Location: http://elsewhere/` would hand a third party the
  viewer's bearer, the capability minted for them and this workload's own
  credential. Every client is built with `ErrUseLastResponse`, the transport
  refuses any destination that is not the gateway's origin, and nothing is
  proxied — the default transport's `ProxyFromEnvironment` would dial these
  requests to an arbitrary egress host under a `NO_PROXY` that misses the
  in-cluster name.
- **The listener bounds a stalled peer.** A request's headers must arrive
  within ten seconds and a keep-alive connection nobody uses is closed after
  thirty; neither bounds a whole request, because a declared long-running
  stream is conforming traffic.

An `https` gateway is still accepted — an operator pointing `GATEWAY_URL` at
an edge presenting a public certificate — and is verified against the system
roots, which is the right anchor for a public edge and was the wrong one for
the in-cell SVID world this replaces.

## One credential per execution

A shared process holds a separate workload credential for each organisation and
installation. `ForModule` checks the published ceiling before asking the broker.
The request uses the host-stamped organisation selector; the returned credential
must match both that organisation and the stamped installation. Core reads the
capability; the host remains responsible for authenticating it and enforcing
live consent, workload admission and approved build.

`Serve`, health, HTTP/MCP route entry, viewer-only forwarding and install
acknowledgement make **no credential acquisition or renewal requests**. A
component with no authority-consuming declaration does not require broker
credentials. Host-driven installation uses its incoming installation capability.

Each scope has one bounded acquisition flight and its own held credential and
backoff. Request waits are bounded by cancellation and 500ms; an acquisition
continues on its own bounded context so one cancelled waiter does not cancel
other callers. At most 256 scopes are retained. Idle scopes may be evicted;
scopes with active callers or acquisitions cannot be evicted. A shared projection
read slot prevents blocked token reads accumulating across replaced scopes.

Actual work reuses the credential before its renewal lead. Renewal rereads the
projection, rechecks frozen authority before and after the mint, and preserves
the execution's image digest/build incarnation across all scopes. Broker expiry
may shorten, never extend, the signed lifetime. A transient failure permits a
held unexpired credential; expiry or a refusal prevents use. The host continues
to enforce revocation on each protected operation.

`401`/`403` are refusals; `412`, `503`, missing projection and transient transport
failures are unavailable conditions. Other protocol/configuration failures are
retained as errors. Every failed acquisition starts bounded backoff. A refused
scope can re-open its source when later work arrives after that backoff, so
changed organisation consent can recover. No background timer retries. One
scope's refusal never stops the shared listener or another installation.

The host-owned SDK's uncached `MintModuleWorkContext` owns the wire contract;
this runtime owns acquisition policy and its admitted, origin-pinned transport.
Redirects and proxies are disabled. `CredentialSource` retains its SDK-compatible
signature; a supplied source must return a credential matching the requested
scope and frozen execution. No public per-organisation factory is introduced.

A viewer mint this runtime cannot attest is not sent. HTTP callers receive a
sanitized unavailable response; MCP tool errors are sanitized before delivery.
Broker status/class/category survive internally, but response bodies, parser
messages and transport causes do not. A Work Context authorizes work; it never
registers a process or establishes its presence.

**Nothing is inferred from a module's 409.** A capability is held until its own
expiry, whatever a callee answers. A 409 means "the state you were sealed to
has moved" and it means "that page already exists", and nothing on the wire
says which — so a runtime that read one as supersession evicted a perfectly
valid capability every time a module reported a duplicate or a lost update, and
the next call minted again. Matching installation metadata identifies the
*scope* of a conflict; it does not establish supersession.

A genuinely superseded capability is therefore refused call by call by the far
end — correct if noisy — and the renewal that replaces it happens on the
credential's own schedule. Acting on a conflict needs a machine-readable
discriminator from the host or the verifier, which nothing publishes today;
what a viewer sees meanwhile is the 409 itself.

A consumer whose issuer is reached another way supplies its own source:

```go
solution.New(manifest).Credential(mySource).Serve() // Credential(ctx) (workcontext.Credential, error)
```

Source errors preserve only the `ErrMintRefused` and `ErrMintUnavailable`
classifications; text and underlying causes are discarded before callers or
logs can receive them. Other source failures get a fixed failure message.

### This runtime neither signs, parses nor verifies a capability

There is **one** implementation of a Work Context — Core's (`core/workcontext`:
deterministic proto, Ed25519) — and this runtime is not it. It obtains a
credential through the module broker client, carries it as the string it travels as,
and lets whoever consumes it decide. It declares none of a capability's fields
and reads none of them: the capability a handler's gateway presents to a module
is a string this package never decoded, and the one check that must happen
before a call rather than at the far end — that a capability is sealed at all —
is the carrier's (`workcontext.Attach`).

It also does not **verify**, and that is a position rather than an omission.
Core's verifier requires four live sources — the authorization revision,
replay, grants and seals — and refuses everything without them, deliberately,
so the strongest check in the model cannot become the easiest to skip. A
solution runtime holds none of those: it is the party presenting a capability,
not the party deciding on one. So there is no verifier here to configure, and a
change that adds one has to answer where those four sources come from.

Core's conformance kit is still run, through the boundary this package does own:
all 39 fixtures are offered to the carrier, and each one's refusal is attributed
to a side. A capability whose bytes are visibly not a capability — no separator,
an unreadable payload, no seal, another encoding — is refused here, before a
request is sent, with Core's own sentinel. A tampered payload, an unknown key,
an audience in the payload and every sealed value the issuer has moved past are
carried, because judging them needs those four sources and a carrier that
refused them would be claiming a strength it does not have. The classification
is per fixture, so a fixture Core adds fails the test until somebody decides
which side it belongs to.

Both halves are pinned by `work_context_boundary_test.go`, which fails on a
signing primitive, on a `WorkContext`-named type or function of this package's
own, and on a call to a verifier. The duplication it prevents already happened
once, in a module whose only job was to carry these things, and 3,532 lines had
to be deleted to get back to one implementation. Every step of that was locally
reasonable, which is why the first step fails a test here.

A module's refusal of a presented capability reaches a handler by kind:
`ErrRevoked` — the capability was sound when minted and the state moved under
it (an installation revision, a principal's epoch, a build incarnation, a
binding) — is reported as `aborted`, because the call was not made and
retrying the same call will not make it. It does **not** retire the capability:
see "Nothing is inferred from a module's 409" above, since that answer is
indistinguishable from an ordinary business conflict. `ErrInvalid` and `ErrNotACoreToken` are reported as `internal`: a
credential this solution could not present is this solution's problem, not a
module that is briefly unreachable. There are two, not three: core v0.9.0
**deleted** `ErrUnsealed`, because the seal is now required by the schema and
`protovalidate` refuses a capability carrying none before any seal check is
reached — so that case arrives as `ErrInvalid`, and a consumer who wrote a
branch for the dedicated sentinel had one that could never run.

## The published contract

A solution **declares** the most authority it may ever ask for: which audiences
it holds bindings for, and the ceiling on each. The runtime holds its own asks
to that declaration at boot, and answers it at `/.well-known/module-contract` so
an operator can read what a process holds itself to.

> **This is not the document the renderer derives authority from.** That is
> `module.contract.codefly.yaml`, YAML, strict-decoded, read at the module
> directory the composition resolved, under the schema
> `codefly/module-contract/v1` — a shape whose audiences are
> `{from: <group>/<key>}` slots a composition resolves per environment, rather
> than ceilings keyed by profile (codefly-dev/cli#855). The runtime publishes
> JSON under its own schema string, `codefly/solution-runtime-contract/v1`, and
> nothing in this package writes the renderer's file. The two were briefly under
> one schema string, which is worse than a mismatch: strict decoding refuses the
> unknown fields, and a matching string makes that read as a *malformed* module
> contract rather than a document meant for someone else.

```go
solution.New(manifest).
    Consumes(solution.ConsumedModule{
        As:     "documents",
        Scopes: []solution.Scope{{ResourceKind: "documents", Actions: []string{"read"}}},
        Methods: []solution.ConsumedMethod{ /* … */ },
    }).
    Contract(solution.ModuleContract{Ceilings: map[string]map[string][]solution.Scope{
        "local":   {"documents": {{ResourceKind: "documents", Actions: []string{"read", "list"}}}},
        "staging": {"documents": {{ResourceKind: "documents", Actions: []string{"read"}}}},
    }}).
    Serve()
```

The ceiling is **declared, never derived**. A ceiling computed from what the
code asks for would be satisfied by construction — a method that asked for one
more action would widen the ceiling meant to refuse it, and a reviewer approving
the contract would be approving whatever the next commit asks for. What *is*
derived is the binding set: the audiences are the `as` of the solution's
`api.consumes` entries, which Codefly projects and the declaration is already
checked against, so restating them would be a second source for one fact. The
principal is neither: it is the `module-authority` value the platform
provisioned, so the contract reports who this workload actually is rather than
who its author believed it would be.

Keyed by **configuration profile**, because a deployment and a developer machine
do not grant the same authority. A deployed environment reads its own profile —
`staging`, say — and never the local one; that distinction is recent
(codefly-dev/core#687, closed in core v0.7.1), and the keying is what makes the
old mistake impossible. A contract that declares only `local` is refused in a
deployment, naming the profile it ran under, the profiles the contract does
declare, and the override that changes it.

Every one of these is a boot failure naming the value:

| Refused | Because |
|---|---|
| no ceiling for a consumed audience | this runtime would have no declared ceiling to check a mint against, for a module it does call |
| a ceiling for an audience nothing consumes | the ceiling governs a call that cannot happen, and whoever wrote it believes otherwise |
| an ask outside its ceiling (action, or resource id) | the ceiling is what a reviewer approved; widening it is an edit, not an inference |
| an ask across a whole resource kind under a ceiling naming resources | "every document" is not inside "these two documents" |
| a ceiling on a `ViewerBearer` module | it mints nothing, so the ceiling governs nothing — and whoever wrote it believes it does |
| no profile at all, for a solution that mints authority | a deployed process would have no profile to resolve its ceiling from |
| a profile name that is not a single path component | profile names select directories wherever one is read |

A running solution publishes the contract of the profile it runs under at
`/.well-known/module-contract` — the resolved principal, the profile, and each
binding with its ceiling and the ask inside it. Nothing is pushed: answering
there makes this solution present to nobody. `ContractArtifact(id, contract,
modules...)` renders the same document at build time, with every profile and no
principal — that is a value only the deployment knows — checked by exactly the
rule the boot applies, so a contract that would refuse to boot cannot be
published. It is for review and for diffing a build, not for the renderer.

### Where the host reaches the solution

Neither address this runtime used to report is reported any more: the presence
document names the route and the destination, and the host resolves both.

- The **Module Federation manifest** is served at `/assets/mf-manifest.json`,
  a path on this backend, and that is the whole of what this runtime says about
  it. It used to be an absolute URL, built from `PUBLIC_URL` or — with none set
  — from this process's own listen address, so every deployed solution
  registered a manifest no browser could load and the product showed it as
  failed to load. The origin a browser reaches this solution through is the
  host's route, and naming the host's route layout here would couple every
  solution to it.
- The **address the gateway dials** is in the presence document's endpoints,
  resolved by the gateway through the SDK from the carrier the CLI hands it,
  exactly as for a module. Nothing here reports it: the advertised origin this
  runtime used to send with its mint, and the `CODEFLY__SELF_ENDPOINT__…`
  carrier it read it from, are gone with the report. A deployed solution once
  registered its own loopback listen address and was proxied by the gateway to
  the gateway itself; an address the composition wrote cannot be that.

This solution still publishes what it is, at fixed paths, for anything that
asks: `/.well-known/solution.json` (the manifest: nav, the exposed module, the
federation manifest path, the backend's service alias, declared surfaces and an
optional dashboard, all from [the declared frontend](#the-declared-frontend)),
`/.well-known/capabilities` (the contract id and the majors),
`/.well-known/module-contract` (the authority contract above) and `/health`.
Publishing is not announcing — nothing is pushed, and answering makes this
solution present to nobody: the host builds its registry entry from the
delivered presence document and its own constants, never from this route.

`/health` reports process health without acquiring or renewing a credential.
It answers 200 while idle, when installed nowhere, and after a scoped refusal.
It makes no authorization claim: each module operation uses its scope's
credential and remains subject to the host's live consent and revocation checks.

The manifest declares the majors it is built against rather than leaving a
reader to assume them — `schemaVersion: 1`, this runtime's manifest schema, and
`frontend.hostContract`, the host contract the author declared — and the
capability document declares the same majors from the same places, so a bump
cannot leave one document announcing the old major while the other announces
the new one.


### The declared frontend

A solution declares what the host lists it under in **one file**,
`solution.frontend.codefly.yaml`, beside the backend's `service.codefly.yaml`.
The backend embeds it — `//go:embed solution.frontend.codefly.yaml` into
`Manifest.Frontend` — and serves its manifest from it; the CLI reads the same
file into the presence document's `frontend` block (core's
`solutionhost.Frontend`), which is what the host's registry projects. Two
readers of one file cannot disagree, where a Go field beside a file could, and
nothing is reported at mint any more. The declaration is optional for either
component kind: a nil `Manifest.Frontend` is headless. A present malformed file
is refused by the same Core reader used by the CLI.

```yaml
title: Widgets           # nav title; one non-empty line
order: 10                # nav order; declared, zero included
exposed_module: ./Page   # the Module Federation module the host loads the page from
host_contract: 1         # the host page-contract major the page is built against; >= 1
dashboard:               # optional: a mapping the host's data-graph validator reads,
  events: [...]          # served and delivered as JSON, at most 64 KiB encoded
surfaces:                # optional: what the solution offers inside a client
  - id: footnote         # lowercase letters and digits, dashes between; unique per client
    client: word         # word, powerpoint, excel or slack
    title: Footnote
    description: Cite a claim.          # optional
    module: /surfaces/word/footnote.js  # a rooted path on this solution's own origin
    contract: 1                          # the surface contract major; >= 1
    applies: always                      # declared: "always", or {tagged: [one or more tags]}
    events: [documents.entry]            # optional; journal namespaces the surface reconciles on
```

The file is YAML, decoded strictly — an unknown key is refused by name — and
its top-level mapping is the block itself, with no wrapper and no schema key:
its keys are core's field names, field for field. Every scalar is declared,
because core refuses an omitted one rather than reading it as zero. The
dashboard is opaque to this runtime but has to be the JSON object the host
reads: a mapping, every key a string, no fraction (JSON spells those more than
one way, and the presence document is canonical bytes), bounded at 64 KiB
encoded. A surface declares its `applies` selector — `always`, or
`{tagged: [...]}` naming one or more tags — because core carries no default,
and names each of its `events` once, as a lowercase dotted journal namespace
(segments of letters and digits separated by a dot, dash or underscore). What
a tag selects and what a namespace names are the client's to interpret; the
shapes are what core signs.

`Manifest` keeps `ID`, `Contract` and `Capabilities` as Go fields: the id is
what the presence document names the solution by, and the capability handshake
at `/.well-known/capabilities` is the backend's own, which the frontend block
does not carry. `Title`, `Order`, `ExposedModule`, `Dashboard` and `Surfaces`
are gone from it with the `Surface` type; the MCP metadata document's
`resource_name` is the declared title.

### Serving the frontend

`/assets/` serves the built Module Federation remote, with CORS, from
`Manifest.Assets` when the solution sets it — typically an `embed.FS` narrowed
with `fs.Sub` to the build's output directory — and otherwise from the
`ASSETS_DIR` directory. A solution serving from `Manifest.Assets` reads nothing
from disk, so it runs with a read-only root filesystem. Either way a file whose
name carries a content hash (`123.3f9a1c2b.js`) is served
`public, max-age=31536000, immutable`, and everything else — `mf-manifest.json`
and the remote entry above all, whose names never change — `no-cache`, as is
any response that is not the file (a `404` for a hashed name must not be cached
under the name the next build will serve).

### Consumed-module federation

A solution that declares `api.consumes` reads each consumed module through the
gateway's `/v1/<as>/*` prefix. **Those routes are delivered**, like everything
else: the gateway holds them in its durable registry, from the presence
documents, and this runtime registers no upstream for them. The three
heartbeats that used to — one per consumed module, each brokering a signed
prefix-bound token through the gateway, plus the two self-registrations — are
deleted, along with the credentials they carried.

Codefly still projects the targets into `CODEFLY__API_CONSUMES`, and that
projection is still what the passthrough declaration is checked against — at
boot, resolved like every other value, so a malformed one is a refusal rather
than a log line. It used to be read at serve time: a malformed projection
disabled the whole federation with one log line while the solution served on,
so every consumed facade 404'd at the gateway and the solution looked healthy.

The refusal fires **whether or not the solution declares a passthrough**. Being
resolved at boot is not the same as being judged there, and for a release it
was only the first: the projection was decoded by the code that consumes it,
which returns early when there is no `Consumes` declaration, so the same
undecodable value was refused for one solution and served for another. It is
decoded once at boot now and refused either way, naming `CODEFLY__API_CONSUMES`
— the projection is the composition's output, so no override an operator can
set repairs it, and `codefly run solution` is where it is fixed.

Unset is not malformed. A solution that consumes nothing leaves the variable
empty, and whitespace alone counts as empty, so a render emitting a bare
newline for it does not fail a boot.


### Reading a Work-Context-authenticated module

The gateway client a handler receives forwards the viewer's bearer. That is
enough for the accounts API, but not for a module that authenticates by signed
**Work Context**: it derives tenant and subject from `x-codefly-work-context`
and answers `Unauthenticated` to a bearer alone. The gateway only verifies and
forwards a context that is already presented — nothing mints one for the viewer
— so `Gateway.ForModule` does:

```go
docs, err := gw.ForModule(ctx, "documents",
    solution.Scope{ResourceKind: "documents", Actions: []string{"read"}})
if err != nil {
    return nil, err
}
resp, err := solution.Unary[Req, Resp](ctx, docs, "/docs.v1.Documents/List", &Req{})
```

`ForModule` mints a Task Work Context through accounts' `StartTask`, presenting
the viewer's bearer so accounts resolves the same subject the module would have
seen, and this execution's own credential beside it so the issuer knows which
module is asking (see [One credential per
execution](#one-credential-per-execution)). It names no actor principal, which makes the viewer both owner and actor
of the Task; the audience is the module; the authority is the scopes asked for
and nothing more. The returned gateway then carries **both** credentials — the
bearer and the capability — on every request, so a module verifying either one
is satisfied.

The returned gateway holds the *ask*, not the capability: it resolves one per
request. A handler may therefore keep it for as long as it keeps the viewer's
request. A capability captured once at derivation would lapse while the handler
still held it, and the gateway verifies freshness on any presented context
*before* routing — so a stale one is rejected at the edge and never reaches the
module at all, which is worse than the bearer-only client it replaced.

The audience is the module's facade entry-point: the `as` of its `api.consumes`
target above, which is both what the gateway routes `/v1/<as>/*` to and what the
module verifies as its own audience. A solution declares the consumption once
and names it here.

A mint is scoped to one organization, which the bearer does not carry. It comes
from `x-org-id`, one of the canonical identity headers the gateway injects after
authenticating the caller; a request reaching a handler without it is refused
here rather than sent to accounts to be refused there. The gateway injects that
header from the caller's *active* org, so it arrives present-but-empty for a
viewer with no organization selected and for an org-less API key — the refusal
names both shapes, because pointing only at an absent header sends whoever
reads it to inspect one the gateway demonstrably did set.

The Task is rooted in the viewer's **session**, which arrives the same way:
`x-session-id`, stamped from the same verified claims and replacing anything the
caller sent. That session is the one accounts sealed the selected organization
into, so the Task it roots is attributable — the mint accounts journals names the
session that asked for it. A session id the runtime invented would be a
well-formed UUID naming no session, attributable to nothing.

Every mint also **names the installation it acts under**. The host requires it
(core's `StartInput.InstallationID`) and refuses a mint naming none, and an
organization is not a substitute: one org may hold several installations, so a
capability minted without naming one is attributable to the org and to no
deployment inside it.

For a viewer-driven mint it is the viewer's own, read from the
`x-codefly-installation-id` header the gateway stamps — on the same footing as
`x-org-id` and `x-session-id`, which the gateway also stamps from verified
claims and replaces whatever the caller sent. A request naming no installation
is refused, and the refusal is deliberately *not* a `ClientError`: no caller
can stamp one, so telling a viewer to fix it would point them at something that
is not theirs.

This section described the opposite for two rounds — the installation read from
the **seal** of a carried capability, with the header as a fallback. That is the
SDK's rule for the direction where a capability *is* the authority being
carried: outbound, where `Attach` puts the seal's own installation beside it and
the far end refuses the two if they disagree. Inbound, that carrier is
caller-controlled — a browser can send `x-codefly-work-context`, and a
caller-supplied capability authenticates nothing here — so reading the
installation out of it would let a caller name the deployment their own mint is
attributed to.

A background or delegated call would carry the installation its parent
capability was sealed to, read off this execution's held credential. **This
runtime has no such path today** — every mint it makes is driven by a viewer
request, and `ForModule` refuses one without an organization and a session.

This execution's own credential is sealed to an installation by the host, from
the projected service-account token; the runtime names none on that mint and
cannot: the broker request contains only the declared prefix. What it does is
refuse a credential sealed to no installation at all, and refuse a *renewal*
sealed to a different one than the credential this process has been acting
under: that is a different identity arriving through the renewal path, not a
renewal, and it would make the mints before and after it name different
deployments with nothing recording that they did.

**An MCP tool call is held to the same credential as a handler.** A tool
receives a gateway carrying the viewer's bearer, so running one while the issuer
has withdrawn this execution's credential is acting for a viewer without
authority — and a tool that mints nothing still sends that bearer wherever it
dials. Every MCP method except the handshake, the keepalive, the listings and
notifications goes through the same check a handler route does, and the viewer
is told the same sanitized sentence. The list is of the methods that act for
nobody, so a method a future MCP SDK adds is checked rather than exempt.

**An MCP error result never names an address this runtime dialled.** A tool's
own refusal reaches the agent client unchanged, but a result that would carry
the mint's or the gateway's address — in its text, or in its structured content
— is replaced with one sentence, and the replacement is logged with what was
caught. What is published is built from strings and bytes this runtime owns:
every marshaller runs first, then nothing is inspected that is not about to be
published. Content whose serialization this runtime cannot read is replaced
rather than passed on.

Rooting the Task there does **not** make the capability revocable, and nothing
here should be read as saying it does. The edge verifies a presented context's
signature and validity window, not the liveness of the session named in it, so
revoking a session stops the *next* request — at the gateway's own revocation
check, before any mint — while a capability already minted stands until its own
expiry. That expiry, not the session's, is what bounds one; accounts caps a
Task's requested TTL at 15 minutes.

Each boundary is refused rather than guessed, and each refusal carries a
`ClientError`, so a handler that returns it answers a status the caller can act
on instead of the generic 502: no active organization is `409`, no session is
`403`. The second has a consequence worth stating outright — **an API key cannot
read a composed module**. It authenticates a principal and no session, so the
gateway stamps `x-session-id` empty, and accounts requires a Task to name one
(`session_id` is a required UUID on `StartTask`). A solution could previously
mint for such a caller only because this runtime invented a session id, which is
exactly what made the capability attributable to nothing. The user-absent path
accounts does provide is the headless installation mint, which this runtime does
not implement.

Neither boundary is ever taken from the handler or from anything a browser sent:
a solution names the audience and the scopes, and the runtime names who the
viewer is.

Minting is an audited event on accounts, so capabilities are cached under the
ask they were minted for and shared by every gateway derived from the one a
handler was given: a handler reading a module repeatedly mints once, and so does
one that fans the same ask out across goroutines — concurrent asks wait on the single
mint in flight rather than each running their own. The cache lives no longer
than the request, since the gateway that owns it does not.

The cache refuses to accept an expiry it cannot use, rather than caching one it
can never reuse. An expiry that is absent, or that this host's clock reads as
already gone by, would otherwise read as "always lapsed" — every call correct,
no error, no log, and one audited mint per read. Both are reported, separately,
because an issuer that omitted `expiresAt` (or spelled it `expires_at`, as
protobuf JSON does) and a host clock skewed past the credential's lifetime have
different fixes. A capability whose whole life is shorter than the renewal lead
is not refused: the lead is clamped to half its lifetime, with a one-time log,
because how long a credential lives is the issuer's call and not this runtime's
to veto.

This traffic is never proxied: every gateway target is composition-local (its
address is resolved from the SDK's endpoint map), and these requests carry the
viewer's bearer and the capability minted for them in headers. The credential
mint this runtime runs for itself is not proxied either, and refuses to follow
a redirect: it presents the projected token that attests which workload this
process is, and `net/http` strips only `Authorization`, `WWW-Authenticate` and
`Cookie` when a redirect crosses hosts — so anything able to answer at the mint
URL with a `Location` would be handed that token, and the theft would look like
an ordinary successful mint.

### Calling a composed module over its REST binding

The gateway reaches a composed module only under the REST prefix the solution
federates for it (`/v1/<as>/*`), so the module's generated gRPC or Connect
client cannot be pointed at it: its procedure paths are not under that prefix.
What the module does publish is each RPC's `google.api.http` binding, in its
generated descriptor. `Gateway.Transcoded` speaks that binding with the
module's own generated messages:

```go
docs, err := gw.ForModule(ctx, "documents",
    solution.Scope{ResourceKind: "documents", Actions: []string{"read"}})
if err != nil {
    return nil, err
}
var page documentsv1.ListCollectionResponse
err = docs.Transcoded(ctx, "/v1/documents", documentsv1.DocumentsService_ListCollection_FullMethodName,
    &documentsv1.ListCollectionRequest{PageSize: 500}, &page)
```

The call uses the method's first binding — the primary rule, then its
additional bindings in order — whose path lies under the prefix. The URL, the
HTTP method, and which request fields go into the path, the query or the body
all come from the descriptor. The caller can name no path of its own, and a
method with no binding under the prefix is refused before anything is sent, as
is a multi-segment path variable, an empty or dot-segment path value, and a
request or response of the wrong type. The response is decoded with unknown
fields discarded and is bounded (`MaxResponseBytes`, 8 MiB by default). A
non-2xx answer is a `*GatewayError` carrying the status.

`Gateway.OrgID` is the viewer's active organization, the same one `ForModule`
mints in. A handler scoping a module read to a tenant names this one.

`Gateway.WorkContextPrincipals` reports whom a `ForModule` capability was
issued for — the organization, the Task's owner and its current actor, as
accounts answered the mint — so a handler compares a claimed owner against
accounts' own resolution instead of trusting it. It reuses the cached
capability rather than minting again.

### Letting the page call a consumed module: the passthrough

The host proxy forwards a solution's page only to the solution's own backend,
so a page cannot reach a composed module's `/v1/<as>/*` prefix, and a module
that authenticates by Work Context would refuse its bearer anyway. Instead of a
handler per module operation, a solution declares which operations its page
may call:

```go
solution.New(manifest).Consumes(solution.ConsumedModule{
    As:     "documents", // the `as` of its api.consumes entry
    Scopes: []solution.Scope{{ResourceKind: "documents", Actions: []string{"read"}}},
    Methods: []solution.ConsumedMethod{{
        Name:     documentsv1.DocumentsService_GetDocument_FullMethodName,
        Response: solution.MustFieldMask(&documentsv1.GetDocumentResponse{}, "document.entry"),
    }},
})
```

Each declared method is served as a Connect unary procedure at
`/modules/<as>/<package.Service>/<Method>`, so the page uses the module's own
generated client (connect-es) unmodified, with the base URL
`<apiBase>/modules/<as>`. A call is answered by the module as the viewer: the
runtime mints the viewer's Work Context with the declared scopes (`ForModule`),
or, with `ViewerBearer`, forwards only the bearer to a module that
authenticates the viewer itself, and forwards the request over the method's
binding (`Transcoded`). The page names a procedure and a request message,
never a path, a prefix, an audience or an authority, and authorization stays at
the module.

Authority is minted per method. A method may declare its own `Scopes`, which
replace the module's for a call to that method — never add to them — so one
module's methods that need different authority are declared under one `as`:

```go
solution.ConsumedModule{
    As: "tasks",
    Methods: []solution.ConsumedMethod{
        {Name: ownListMethod, Scopes: []solution.Scope{{ResourceKind: "tasks", Actions: []string{"list"}}}, WholeResponse: true},
        {Name: orgListMethod, Scopes: []solution.Scope{{ResourceKind: "tasks", Actions: []string{"inspect"}}}, WholeResponse: true},
    },
}
```

Each call mints only its own method's authority. A viewer who lacks one
method's authority is refused that method as `permission_denied`, with the
fixed refusal message, and is still served
every other method; the mint is never widened or retried with less. Every
method of a module that is not `ViewerBearer` needs scopes, its own or the
module's, and `ViewerBearer` takes none at either level.

Least privilege by default. A method that is not declared is `not_found`. At
boot, `Serve` refuses a module whose `as` is not in the solution's api.consumes,
a method missing from the registry or with no binding under `/v1/<as>`, a
client-streaming method, stream bounds on a unary method or out of range, a method with no declared response fields, a method with no
scopes of its own or its module's (unless the module is `ViewerBearer`), scopes
on a `ViewerBearer` module or method, and a scope with no resource kind, no
action, or a blank or repeated action. `Response`
names the fields returned to the page; `WholeResponse` must be said explicitly.
`Pin` fixes part of every request server-side (merged with `proto.Merge`): a
pinned scalar replaces the page's value and a pinned repeated value is added to
the page's, so a filter clause the module ANDs stays in force whatever the page
sends.
A module's refusal reaches the page in the Connect error: a `google.rpc.Status`
body keeps its code and message, any other small JSON refusal is the message
verbatim under the code its HTTP status maps to, and a **4xx** refusal written
as short, single-line plain text — the shape the host gateway writes, "module is
not installed for this organization" — is the message too. A 5xx body is
reported by kind only: it may be written by an intermediary and name an internal
address, which the caller must never read. `PassthroughOperations` renders the declaration for the interface
artifact, and `InterfaceArtifact(dir, info, ops, modules...)` renders a
backend's whole artifact — its own operations and the passthrough — at the
version its `service.codefly.yaml` declares.

#### Streamed methods

A server-streaming method passes through too, as a Connect server-streaming
procedure at the same path, so connect-es's generated client consumes it
unmodified. It takes the same authority as a unary call — the viewer's Work
Context minted for that method, or the bearer alone for a `ViewerBearer`
module — and the declared response fields (`Response`, or `WholeResponse`)
apply to **every** message of the stream.

Every stream is bounded, and both bounds are declared per method:

| Field | Default | Refused at boot |
| --- | --- | --- |
| `MaxStreamDuration` | `DefaultStreamDuration` (5 min) | negative, or over `MaxStreamDurationLimit` (30 min) |
| `MaxStreamMessageBytes` | `DefaultStreamMessageLimit` (1 MiB) | negative |

A stream that reaches its duration ends with `deadline_exceeded`; a message
over its bound ends it with `resource_exhausted` and is never truncated. For a
streaming method `Timeout` bounds only the mint and the module's first answer
(status line and headers), and `MaxResponseBytes` is refused (bound each
message instead). The page disconnecting cancels the module request at once.

**The wire a module answers a streamed method with** is grpc-gateway's for a
server-streaming method, over the method's `google.api.http` binding: a 2xx
response with content type `application/x-ndjson` (`application/json` is
accepted too), one JSON object per line, each flushed as it is ready:

```
{"result": <the message, in protobuf JSON>}
{"error": {"code": <google.rpc.Code number>, "message": "<text>"}}
```

Blank lines are ignored, so a module may send them to keep an idle connection
open. An error line ends the stream with that code and message; the end of the
body ends it normally. A non-2xx answer before the stream starts is the
module's refusal, relayed like a unary one. `Gateway.TranscodedStream` is the
same call for a handler of the solution's own.

In the interface artifact a streamed operation says so in its behaviour and
carries `x-streaming: server` (Swagger 2 has no stream; its 200 schema is one
message of it).

#### Testing the passthrough: `passthroughtest`

`Serve` resolves the gateway and api.consumes from the composition, mints this
execution's credential and listens on the resolved port, so a solution
cannot run its own passthrough in a test through it. Package
`github.com/codefly-dev/solution-runtime-go/passthroughtest` serves the real
passthrough — the handler `Serve` mounts, behind
the same boot check — over an `httptest` server, against a fake host:

```go
upstream := httptest.NewServer(fakeWidgets) // the test's stand-in for the module's binding
host := passthroughtest.NewHost(t).Module("widgets", upstream.URL)
page := passthroughtest.Start(t, host, declaration...) // the solution's Consumes
client := widgetsv1connect.NewWidgetsClient(page.Client(), page.BaseURL("widgets"))
```

| API | What it is |
| --- | --- |
| `NewHost(t)` | The fake host gateway: it mints the viewer's Work Context (the accounts `StartTask` procedure) and forwards `/v1/<as>/*` to each routed module, streams included, flushed as they arrive. |
| `Host.Module(as, upstream)` | Routes a consumed module to the test's own server, path unchanged. Every routed module is also in the solution's api.consumes; one the declaration names but the host does not route is refused as `Serve` refuses it. |
| `Host.RefuseMints(func(Mint) *Refusal)` | Decides each mint: a non-nil `Refusal` refuses it as accounts would (default status 403), so the page sees `permission_denied` with a fixed refusal message. |
| `Host.Mints()`, `Host.Calls()` | Every mint asked for (audience, scopes, org, session, bearer, the token answered), and every call forwarded to a module, each with the `Mint` whose capability it presented — how a test asserts the authority each method was called under. |
| `Start(t, host, consumes...)` / `Handler(host, consumes...)` | The passthrough served for the declaration, or the bare handler and the error `Serve` would refuse the declaration with. |
| `Solution.Client()`, `ClientAs(Viewer)`, `BaseURL(as)` | A client that calls as `DefaultViewer` (or the viewer given), setting the bearer and the `x-org-id` / `x-session-id` headers the gateway stamps; and the base URL a module's generated client takes. |

What a green test there proves is the solution's side: the declaration, the
authority each method mints, the fields that reach the page, stream bounds and
cancellation. It never proves that a real host admits the solution, that
accounts grants the scopes, or that the real module answers its binding the way
the test's stand-in does.

**This seam is reachable only from here.** `Server.PassthroughHandler` was
exported until this change, and that made it a production bypass: a solution
could build a usable, credential-bearing handler that had skipped `validate()`,
the boot, the published ceiling and the origin-pinned outbound client — a
deployment calling it completed a viewer mint and a module call and answered
200, with the viewer's bearer and this workload's own credential sent wherever
it was mounted. Supplying a credential source, which a deployment does,
defeated the "no source, nothing to mint with" mitigation. It is reached
through `internal/seam` now, which Go's internal-package rule keeps inside this
module. The fake host is still plaintext and still has no contract, and those
are now properties of this module's own tests rather than of an API. A consumer
that called `PassthroughHandler` directly uses `passthroughtest.Handler`
instead.

`passthroughtest` itself is importable by any module, so its own constructors
**panic outside a test binary** (`testing.Testing()`). Taking a `testing.TB` is
not the gate it resembles: `testing.TB`'s unexported method stops a type
*declaring* the interface, not a type that embeds it, so a few lines of
production code satisfy it. `testing.Testing()` is wrong for the root package —
where the legitimate caller is production code — and exactly right here, where
every legitimate caller is a test.

### Exposing an MCP server

A solution exposes its experience to an agent client — Claude Code, Claude
Desktop, any MCP client — the way it exposes it to a browser: as the signed-in
person, through the host's gateway, with the same authority. The solution owns
its tool surface; this runtime owns serving it. These are the three lines:

```go
solution.New(solution.Manifest{ID: "wiki", Frontend: frontend}). // the embedded solution.frontend.codefly.yaml
    ServeMCP("wiki", "v1.0.0", func(srv *mcp.Server) {
        mcp.AddTool(srv, &mcp.Tool{Name: "ask_wiki", Description: "ask the wiki a question"}, askWiki)
    }).
    Serve()
```

A composition that renders this solution supplies **two** declared values for
it, and only in a deployment, both in the `mcp` workspace-configuration group,
declared as a workspace-configuration dependency of the solution's backend:

- `issuer-url` — the origin MCP clients authenticate against;
- `public-url` — the URL clients dial, ending in `/mcp`.

**This said *one* value, and a deployment following it does not boot.** The
public URL is derived from `PUBLIC_URL` **for a local run only**: a deployed
runtime context refuses a derived identifier, because the derivation encodes
the route the *host* serves this solution on. Both keys are required there, and
the boot names whichever is missing. See [The resource identifier and the
issuer](#the-resource-identifier-and-the-issuer).

`register` receives the official SDK's own `*mcp.Server`
(`github.com/modelcontextprotocol/go-sdk`, pinned in this module's `go.mod`), so
tools, prompts and resources are declared exactly as that SDK documents them and
this runtime adds nothing to them. It is called once, when the endpoint is
mounted.

A tool call runs as the viewer who made the request. `ViewerFromContext` returns
the same caller-bound `Gateway` a `Handler` is given, so a tool reads a composed
module through `ForModule` under the viewer's own Work Context — the identical
call the page makes, with the identical typed refusals:

```go
func askWiki(ctx context.Context, _ *mcp.CallToolRequest, in askIn) (*mcp.CallToolResult, askOut, error) {
    gw, err := solution.ViewerFromContext(ctx)
    if err != nil {
        return nil, askOut{}, err
    }
    notes, err := gw.ForModule(ctx, "notes", solution.Scope{ResourceKind: "conversations", Actions: []string{"create"}})
    if err != nil {
        return nil, askOut{}, err
    }
    ...
}
```

The viewer comes from the identity headers the gateway stamped, never from the
tool's arguments: those are written by a model, and a session id taken from them
would be a client asking for another viewer's authority. `ViewerFromContext`
errors only for a handler invoked outside a request this runtime served — a
harness of its own, or an `*mcp.Server` mounted without `ServeMCP`.

#### What is served, and what is refused

| Path | What |
| --- | --- |
| `/mcp` (`solution.MCPPath`) | Stateless Streamable HTTP. `/solutions/<id>/mcp` through the gateway, a route it already fronts. `POST` only: `GET` and `DELETE` are `405` and no `Mcp-Session-Id` is ever issued, because the gateway is a reverse proxy with no sticky routing — a session held in one replica's memory is unreachable from the next request. The SDK's DNS-rebinding protection is left on, so a request reaching a loopback listener with a non-loopback `Host` header is refused `403`: on a developer's machine that protection is the one that still applies, since a rebound page is same-origin and can forge identity headers that a cross-origin page cannot. |
| `/.well-known/oauth-protected-resource` (`solution.ProtectedResourceMetadataPath`) | The OAuth 2.0 Protected Resource Metadata document (RFC 9728): the `resource` a client binds its token to, the host issuer in `authorization_servers`, and `bearer_methods_supported: ["header"]`. Served unauthenticated, with `Access-Control-Allow-Origin: *`, because discovery is public (RFC 9728 §3.1). |

The MCP endpoint itself carries **no** CORS. The runtime's policy for a
solution's own API admits any origin with an authorization header, which is the
right answer there and the wrong one for the single route that acts with the
viewer's full authority; an MCP client is not a browser page.

The runtime verifies no token: the gateway strips caller identity headers, runs
ext_authz on the bearer and stamps what it resolved, so verifying it again here
would be a second, divergent implementation of the host's admission rules, with
its own JWKS fetch, its own audience logic and its own bugs. What is enforced is
that the gateway did it:

| The request | Answer |
| --- | --- |
| No `authorization` | `401` with `WWW-Authenticate: Bearer resource_metadata="…"`. |
| A bearer, but none of `x-user-id`, `x-org-id`, `x-session-id` stamped | `401` with the same challenge: nothing but the gateway may reach this endpoint, so either the request did not come through it or it did not authenticate the bearer. |
| `x-session-id` stamped empty | `403`, naming the `x-credential-kind` the gateway stamped. A credential that authenticates without a session cannot act for a viewer, and every tool call that does mints a Work Context rooted in one — so this is refused at the boundary rather than once per tool call, where the same refusal would read as the tool being broken. Another token cannot fix it, so it carries no challenge. |

**Which caller sees those two 401s.** Not an MCP client coming through the
gateway: the gateway strips the caller's identity headers and runs ext_authz on
the bearer *before* proxying, so an unauthenticated request is denied there with
its own `401 authentication required` and never reaches the solution. The
runtime's 401 is what a caller reaching this solution directly sees — a local
run, a port-forward, a composition dialling the backend — and it is the shape
the gateway's own challenge has to match for discovery to work at all. Emitting
it at the gateway is the host's half
([codefly-dev/module-saas-starter#1003](https://github.com/codefly-dev/module-saas-starter/issues/1003));
the document that challenge must point at is served here either way.

#### The resource identifier and the issuer

The `resource` in the metadata document is what a client asks the authorization
server for a token for (RFC 8707) and what its token is audience-bound to, so it
must be the **public** MCP URL — not this process's listen address, not the
in-cluster address the gateway dials. A client that is handed any other
identifier rejects it, and unlike the manifest URL nobody downstream can resolve
it on the solution's behalf.

So it is **derived by construction** from the two things the runtime already
has: the origin this product is reachable at and this solution's id —
`<PUBLIC_URL>/solutions/<id>/mcp`. This is the one place the runtime encodes the
gateway's solution route (see [Where the host reaches the
solution](#where-the-host-reaches-the-solution)).

**That derivation is for a local run only, and this said otherwise.** It read
as "a deployment that already sets `PUBLIC_URL` … has addressed the MCP surface
too", and a **deployed runtime context refuses a derived value at boot**
(`mcp.go`, `validateMCP`): the derivation encodes the route the *host* serves
this solution on, which this runtime does not know. So following that sentence
in a deployment failed the boot. In a deployed context the identifier is
**declared** — `mcp/public-url` in the workspace configuration, ending in
`/mcp` — and `PUBLIC_URL` addresses nothing about MCP there.

A host whose gateway fronts solutions under some other route declares
`public-url` in the `mcp` group instead. It must end in `/mcp` — the metadata
document's own URL is derived from it by swapping that suffix, the same pairing
the registration token URLs use, refused at boot for the same reason when it
cannot be made. With neither — no `PUBLIC_URL`, no declared override — the
identifier is reconstructed per request from `x-forwarded-proto`,
`x-forwarded-host` and `x-forwarded-prefix`, and `ServeMCP` logs at boot that it
is doing so: a proxy that forwards no prefix yields an identifier missing the
path it stripped, which a conforming client rejects and a tolerant one binds to
the wrong resource. In a deployed runtime context that state is refused at boot
rather than logged.

`authorization_servers` is the host issuer resolved at boot, never derived from
a request, so a crafted `Host` header cannot point a client at an authorization
server of someone's choosing. It is `issuer-url` in the `mcp` group when the
composition declares one, and otherwise the host frontend's origin resolved by
role like every other host endpoint. That resolved value is the address this
composition reaches the host at: right for a local run, and in a deployment an
in-cluster address no public client could reach — so a deployed solution that
declares `ServeMCP` must supply `mcp`/`issuer-url`, and is refused at boot
naming it when it does not. It stops being the composition's to supply when
[module-saas-starter#1003](https://github.com/codefly-dev/module-saas-starter/issues/1003)
settles what `iss` is. A solution that declares `ServeMCP` and resolves no
issuer at all is refused at boot; one that declares no MCP server is unaffected.

Both values are read with `codefly.For(ctx).WorkspaceConfiguration("mcp", …)`,
never from the environment. `MCP_PUBLIC_URL` and `HOST_ISSUER_URL` were bare
environment variables when `ServeMCP` landed, and a render cannot project one —
so the boot refused with the name of something no composition could set
(codefly-dev/solution-runtime-go#48). Provisioned locally with `codefly config
generate`, and from the cell's configuration when deployed, exactly as the
`solution-registration` group is.

Three things about discovery belong to the host, not to this runtime, all of them
tracked by
[module-saas-starter#1003](https://github.com/codefly-dev/module-saas-starter/issues/1003).
The gateway emits the 401 challenge, as above. It must admit an unauthenticated
`GET` on `/solutions/<id>/.well-known/oauth-protected-resource`, or no client can
read the document that challenge points at. And that is where the document is —
on the solution's own path — whereas RFC 9728 §3.1 also defines a location
derived from the resource's path,
`/.well-known/oauth-protected-resource/solutions/<id>/mcp`, at the **host's**
root. A client that follows `resource_metadata` reaches the document either way;
one that only guesses the derived location needs the host to serve it there.

#### Connecting

Until the host is an MCP-conformant OAuth 2.1 authorization server, a client
presents a token it already has, which the gateway already accepts:

```sh
claude mcp add --transport http wiki https://<host>/solutions/<id>/mcp \
    --header "Authorization: Bearer <access token>"
```

Once the host supports it, the gateway's 401 challenge and the metadata document
above are the whole of what a client needs to authenticate on its own.

#### Testing the tools: there is no supported path yet

**This section documented `s.mcpHandler`, and a consumer cannot call it.** The
method is unexported, so the example could not compile from a consuming
package; it also said `Serve` "registers with the host", which is the thing
this cutover deleted.

It was exported once, as `Server.MCPHandler`, and unexporting it was not a
tidy-up: an exported method handing back a servable handler built without the
boot is the `PassthroughHandler` incident verbatim — a handler that has skipped
`validate()`, the boot, the published ceiling and the origin-pinned outbound
client, carrying the viewer's bearer and this workload's own credential over
whatever it is mounted on. `TestNoExportedPathHandsOutAServableHandler`
fails if it comes back. So the example is removed rather than repaired, and
restoring the export to make it compile is the one fix that is not available.

What a consumer can do today is drive their tools as ordinary functions and
test the authority each one asks for. What is missing is the MCP equivalent of
`passthroughtest` — a seam reached through `internal/seam`, whose constructors
panic outside a test binary, that runs the real MCP surface against a fake
host. That is a follow-up on #45, not a capability this README should describe
as existing.

What a green test there proves is the solution's side: the declaration, the
authority each method mints, the fields that reach the page, stream bounds and
cancellation. It never proves that a real host admits the solution, that
accounts grants the scopes, or that the real module answers its binding the way
the test's stand-in does.

**This seam is reachable only from here.** `Server.PassthroughHandler` was
exported until this change, and that made it a production bypass: a solution
could build a usable, credential-bearing handler that had skipped `validate()`,
the boot, the published ceiling and the origin-pinned outbound client — a
deployment calling it completed a viewer mint and a module call and answered
200, with the viewer's bearer and this workload's own credential sent wherever
it was mounted. Supplying a credential source, which a deployment does,
defeated the "no source, nothing to mint with" mitigation. It is reached
through `internal/seam` now, which Go's internal-package rule keeps inside this
module. The fake host is still plaintext and still has no contract, and those
are now properties of this module's own tests rather than of an API. A consumer
that called `PassthroughHandler` directly uses `passthroughtest.Handler`
instead.

`passthroughtest` itself is importable by any module, so its own constructors
**panic outside a test binary** (`testing.Testing()`). Taking a `testing.TB` is
not the gate it resembles: `testing.TB`'s unexported method stops a type
*declaring* the interface, not a type that embeds it, so a few lines of
production code satisfy it. `testing.Testing()` is wrong for the root package —
where the legitimate caller is production code — and exactly right here, where
every legitimate caller is a test.

> **This whole section was duplicated.** Two near-identical copies of
> "Exposing an MCP server" sat 200 lines apart, which is why correcting one
> passage left the same error in place — the `mcpHandler` example was removed
> twice and the `PUBLIC_URL` claim corrected twice before the cause was
> obvious. The stale copy is deleted.


### Generated messages in a response

A handler's value is encoded with `encoding/json`, which reads a generated
message's Go struct tags rather than producing protobuf JSON. Wrap an owner's
message in `solution.MessageOf(m)` (`solution.Message[T]`) wherever it sits in
the response, and it encodes as protobuf JSON. To pass on only part of an
owner's message, declare a `FieldMask` once from the paths allowed and
`solution.Apply` it. A field the owner adds later reaches nobody until it is
named, and a path naming no field fails at declaration.

### Documented operations

`Server.Operations` registers a list of `solution.Operation`s — each a route,
its handler, and the documentation a reader needs (summary, callers, behaviour,
query parameters, request and response types). `solution.InterfaceDocument`
renders the same list as a Swagger 2.0 artifact, so one declaration is the
source of what is served and what is published, and an operation missing its
documentation is refused. A `Message[T]` field is described from its
descriptor, with protobuf JSON names.

> **Dependency pins.** `go.mod` records the exact Core, SDK and SaaS SDK
> revisions used by this runtime, including unreleased commit pseudo-versions.
> No local `replace` directive is shipped. Core owns capability decoding and
> frontend validation; sdk-go owns resolution, authority reading and endpoint
> admission; saas-sdk-go owns the broker wire client. Local source composition
> does not require publishing a release.

### Shared frontend validation and headless components

`Manifest.Frontend == nil` declares a headless component: it boots normally and
its frontend manifest route returns 404. A present file, including an empty one,
is validated by Core's `solutionhost.ParseFrontend`, the same reader the CLI uses
for modules and solutions before signed delivery. The runtime carries Core's
frontend types and bounds directly; it no longer maintains a client-kind list
or a second set of field validators. Client kinds are declared names, with
support decided by the consuming client.

Core limits text to 1 KiB, surface/event/tag collections to 64 entries, a
dashboard to 64 KiB and the complete canonical frontend to 128 KiB. These are
file/declaration constraints, independent of per-organisation page admission.
