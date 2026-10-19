# Working in solution-runtime-go

This repository owns the generic Go runtime for **codefly solutions** — modules
deployed independently of the host they extend, with no build-time coupling. It
owns what every solution needs identically: configuration resolution through the
codefly SDK, obtaining installation-scoped credentials on actual module work from the projected
service-account token, a plain-HTTP listener on the port Codefly resolves —
the cell's mesh carries transport security and destination identity for every
hop inside it — CORS, Module Federation asset serving, the capability
handshake, the manifest served from the one declared frontend file, the
published authority contract, serving the solution's MCP server to agent
clients, and the gateway client a handler uses to read composed modules on the
viewer's behalf.

**A runtime does not register itself.** Presence is delivered — a signed
presence document declares which solution runs on which host, and the host
reconciles towards it — and authority is delivered the same way, bound to one
approved build. The heartbeat, both self-registrations, the per-beat single-use
token exchange, the consumed-module registrations and every key that fed them
are deleted, not fenced; the host's endpoints for them are deleted in the same
cutover, so a runtime of the previous generation gets 404 and that is the
intended outcome. Health is answered, never pushed. If you are about to add
something that tells the host this process exists, you are rebuilding what this
runtime removed.

It owns none of the counterparts it talks to. The mint endpoint and the
admission rules belong to the host (the composition's own host module) and the
gateway; the authority reader and the one transport rule that admits a
plaintext URL (`workcontext.AdmitEndpoint`) to `codefly-dev/sdk-go`; the broker
wire contract and client to `saas-sdk-go/moduleauthority`; endpoint, port and secret resolution to `sdk-go` as well;
workspace, manifest and presence/authority document types to `codefly-dev/core`;
running a composition, provisioning its secrets and rendering the authority
document to `codefly-dev/cli`. Everything here is a library — one Go package at
the repository root, consumed as the Go module
`github.com/codefly-dev/solution-runtime-go` at a `vX.Y.Z` tag, plus
`passthroughtest`, the test seam a consumer runs the root package's passthrough
under against a fake host. It holds no runtime behaviour of its own: it builds
on the handler `Serve` mounts, reached through `internal/seam`.

**That seam is not public API, and must not become one again.**
`Server.PassthroughHandler` was exported, and a deployment calling it completed
a viewer mint and a module call over plaintext, 200, having skipped
`validate()`, the boot, the ceiling and the origin-pinned outbound client —
with the viewer's bearer and this workload's own credential sent wherever it
was mounted, and supplying a credential source defeated the "no
source, nothing to mint with" mitigation it relied on. Go's internal-package
rule is the gate, which is a compiler rather than a naming convention;
`TestNoExportedPathBuildsACredentialBearingHandlerWithoutTheBoot` fails if an
exported path reappears.

Beside it, the handler-export, capability-decoder and seal-construction gates
are **built on `go/types`**, in `typed_boundary_test.go`, and the fixtures that
drive them are **compiled** into this package through a `packages.Load`
overlay. Two rules follow from resolution that no list could express:
"servable" means **implements `net/http.Handler`**, not a set of types that
happen to; and "core's wire message" means **from core's generated package
path**. What resolution still cannot decide is in that file: a decode
destination whose static type is an interface (`proto.Message`, `any`) is not a
capability by its type, which is the same residual core's own verifier has.

**There is ONE traversal, `typeWalk`, and every rule asks its question through
it.** Four rounds of findings were the same defect — a walk that enumerated the
carriers it knew: a struct, then a map, then a signature result, then an
interface-typed field, then a generic's type argument, then a concrete wrapper
around a capability. Each fix was correct and the next carrier arrived, because
the author picks the carrier. So the walk reaches a **fixed point** over
resolved types: pointer, slice, array, map key and element, channel, struct
field, signature result, interface method result, exported method result, a
named type's underlying type, a generic's type arguments, a type parameter's
constraint. There is no list to extend because there is no list.

It **fails closed in both directions a traversal can go wrong.** Cycles are
guarded by identity, not by a depth cap: the two walks this replaced returned
false past depth 8 and depth 6, so nine nested arrays around an `http.Handler`
escaped both — a traversal that gives up quietly is a gate that can be
exhausted by nesting. And what it cannot resolve is **reported**, not skipped;
every caller turns `unresolved` into a finding, because a gate that cannot see
is not a gate that passes. `TestTheWalkRefusesWhatItCannotFinish` asks that
branch directly, since no fixture can exhaust a 50,000-node budget.

Two distinctions in it are load-bearing, and both were found by the walk's own
first run flagging real code:

- **What a value HANDS BACK is not what its memory HOLDS.** Construction
  follows struct fields and array elements — inline memory — and nothing else:
  a method result, and what a pointer, slice, map or channel refers to, are not
  allocated by allocating the value. Expanding every carrier reported
  `&authorityHeldSource{…}` as constructing a capability, because its
  `CredentialSource` field is an interface whose method returns the SDK's
  credential, which is an alias for one of core's wire messages. A **decode
  destination** does reach through indirection, because a decoder allocates
  through it.
- **A foreign package's type is its own API.** What this boundary forbids is
  THIS package building a carrier for core's wire message; the SDK's
  `Credential` transitively contains them by design. So a named type from
  another package is not expanded into its fields — while a core wire type is
  still matched wherever it appears, however deep, because the match runs
  before any expansion.

The value-flow half is the same walk with a different predicate. A handler
handed out through `struct{ H any }` or `func() any` cannot be decided from the
result type — and refusing every interface-typed field would refuse
`Operation.Request`/`Response`, which are `any` by design — so the rule asks
whether an exported function whose results carry an interface **a handler could
be stored in** also has a mountable value in hand. `error` is an interface and
every function returns one; a handler cannot be stored in it, and asking
whether `http.Handler` implements the interface is what tells the two apart. A
generic is the same shape one level up: `alloc[SealedValues]()` sees a type
PARAMETER at its `new(T)`, so the question is asked at the INSTANTIATION, where
the concrete type exists (`types.Info.Instances`) — and the type ARGUMENT is
then walked, which is how `alloc[box, *box]()` is caught through `box`'s own
field, two type parameters and an alias deep. Indirection is not a shape
either: a `**SealedValues` destination is dereferenced all the way down, and
the RECEIVER of a `Decode`/`Unmarshal` method is a destination as much as its
arguments are.

They were syntactic until round sixteen, and that history is the reason for the
rewrite — the old rule was falsified by a shape nobody had written down, six
times over:
`Routes() func(http.ResponseWriter, *http.Request)`, a named collection, an
import-aliased `nh.Handler`, this package's own bare `Handler` (which the
servable set had always named and never matched, because the renderer had no
identifier case at all), an unexported alias, an unexported struct field, an
anonymous struct result, a supplied decode destination, a zero-value
declaration, an assignment alias, a function-local alias, and `Decode` instead
of `Unmarshal`. Every fix was correct and the next spelling arrived anyway. A
rule that reads syntax is a rule about names, and the author picks the names —
so the rules read types now and there is no list to extend.

Worse than any single shape: two probes asserted against
`workcontext.WorkContextV1`, which the SDK **does not export**, and because a
probe only PARSED its fixture, a name that cannot compile supplied three rounds
of evidence that the whole-capability rule worked. The fixtures compile now.

A gate cannot be mutation-tested — the harness asks "mutate the code, does the
suite fail?", and a gate only fails when the counterexample it exists to refuse
is in the tree — so its acceptance criterion is the compiled fixture set,
driving the rule itself rather than a copy of it. A copy is not evidence: the
signing-relaxation test checked its own copy of the condition and survived the
real condition being removed. The same applies to the seam's refusal: the
defeat check (`recover()`, a branch that cannot be taken) ran only where
`mustBeATest()` was called directly, so the identical defeat one hop away was
*inherited* as a refusal and passed.

`passthroughtest` is itself importable by any module, so that rule alone did not
close this: `passthroughtest.Handler` was an exported, production-importable
path to the same handler, and the gate skipped the package by path while
matching only receiver methods named `*Passthrough*`. Its constructors now panic
outside a test binary (`testing.Testing()`), and the gate reads every caller of
the seam in the module and requires that refusal. A `testing.TB` parameter is
not a gate: the unexported method stops a type declaring the interface, not one
embedding it.

## Boundaries

- Read [README.md](README.md) first. It is the contract this runtime offers its
  consumers and it is kept current with the code, down to the env-override
  table. A behaviour change the README describes is unfinished until the README
  describes the new one.
- Everything `go doc -short .` prints is pinned at a tag by repos you cannot see
  from here — the types a solution author writes (`Manifest`, `Handler`,
  `RequestHandler`) as much as the calls it makes. Read that list before you
  change a signature, a struct field or an exported constant; a change that
  breaks a consumer carries a `!` in the commit type and says so in the PR body.
- Native local listeners bind their SDK-resolved loopback host; `PORT` overrides only the port. Container and Kubernetes listeners retain container-wide binding under platform network admission.
- Boot configuration is resolved in one place, `loadConfig`, and checked in one
  place, `validate()`: resolved through the SDK, with an explicit env override,
  refused loudly when unresolved. New configuration follows both rather than
  reading the environment where it is used. **There is no exception.** There used
  to be one — the consumed-API projection was read at serve time to register each
  consumed module's upstream, and a malformed one disabled the whole federation
  with a log line while the solution served on — and it went with the
  registrations. Every environment read now sits in `loadConfig`'s call tree,
  which `environment_boundary_test.go` pins: a new read outside it fails the
  suite until this file describes the exception — and so does a read reachable
  from the serving surface, because a helper boot shares with serving code sits
  in that tree while running long after `validate()`.
  What precedes `loadConfig` is `codefly.Init`, not a bare
  `LoadEnvironmentVariables`: since sdk-go v0.3.1 the SDK resolves no endpoint
  until `Init` has pinned the consumer module from `CODEFLY__MODULE`, so a boot
  that only loaded the carriers resolved nothing and blamed provisioning.
  `loadConfig` separates `Init`'s two failures and `validate()` refuses an
  unidentified module by name, overrides or not — the SDK's contract is that a
  process failing `Init` does not serve.
- Those gates ask the compiler, not the source text, and that is not a style
  choice: four review rounds each found one more spelling a syntactic rule
  lost. Constants come from `types.Info` (a conversion, a chain, a local
  constant all fold); reachability is CHA over SSA from `golang.org/x/tools`,
  rooted at `serve`, every exported declaration, the package initializer and
  every address-taken function — a handler mounted on a mux is never *called*
  here, so a graph of call expressions has no edge to it. A reader is an
  OBJECT (`os.Getenv`/`LookupEnv`/`Environ`/`ExpandEnv`, `syscall`'s, the
  SDK's accessors, this package's `env`) followed wherever its identity flows,
  with one definition shared by both gates, and an environment key that cannot
  be traced to constants is refused rather than skipped. If you add a gate
  here, resolve rather than match: `facade_claim_test.go` and
  `environment_boundary_test.go` carry the compiled fixtures for every spelling
  that beat an earlier version.
- **Those two gates have no skip, for the same reason `typeWalk` has none.**
  Resolving instead of matching closed the spellings and left the last form of
  the defect in place: a reader value moved somewhere the propagation had no
  edge for — a map of functions, a `reflect.Value.Call`, a generic
  instantiation, a slice — produced *silence* from both gates, which reads
  exactly like a clean package. So the default is inverted. The modelled flows
  are the ones the propagation follows (a name, a variable specification, a
  struct-literal field, a conversion, an argument to one of this package's own
  functions, being called) and a reader in any other position is an
  **unresolved finding**. Teaching it about maps and reflection was explicitly
  not the fix: the author picks the carrier, so the next one would be silent
  again. The four spellings are committed as fixtures because they are evidence
  for the rule, not the rule.
  A dependency's body is not here, so a wrapper of the syscall layer is modelled
  by **summary** — `golang.org/x/sys/unix` beside `os` and `syscall`, which is
  where every environment read in Go bottoms out. A wrapper in a fourth package
  is the residual, and the escape rule is what keeps that residual from being
  silent whenever a reader *value* is what travels into it.
  The propagation reaches a fixed point **or refuses**: stopping after a fixed
  number of rounds was a skip wearing a loop, since whatever had not propagated
  yet simply was not there and nothing said so.
  `TestTheReaderFixpointRefusesExhaustionRatherThanStoppingQuietly` asks that
  branch directly against a reverse-declared alias chain at a one-round budget,
  because no fixture can exhaust sixty-four rounds — the same reason
  `TestTheWalkRefusesWhatItCannotFinish` exists.
- **A gate's fixtures are asserted per site, never in aggregate.** Two of these
  asserted totals and both were satisfiable with a shape missing: three reader
  *names* across seven serving paths passed with the mounted handler and the
  stored method value gone, because another path reported the same reader; and
  counting occurrences of a claim path passed on a single finding, which names
  the shape twice — once as the constant's value and once as the shape matched.
  They assert the function each read sits in, and the distinct sites a shape was
  caught at.
- Resolving a value in `loadConfig` is half the rule; the other half is a
  refusal in `validate()` that fires **whether or not the feature using it is
  switched on**. The `api.consumes` projection was resolved at boot and decoded
  only by the code that consumes it, which returns early for a solution
  declaring no `Consumes` — so one undecodable projection had two answers:
  refused for a solution with a passthrough, accepted and served for one
  without. It is decoded now in `loadConfig` (`parseAPIConsumes`) and refused by
  `validate()` either way, naming the variable it arrived in, since it is the
  composition's output and no override repairs it. `projection_boundary_test.go`
  pins that, including that unset and whitespace mean "consumes nothing" rather
  than "malformed".
- A solution claims no module's facade route and holds no credential that would
  let it: a route for a module is claimed by the module that serves it, under a
  credential bound to that module (#51, SA-F-GWREGISTRY). The passthrough and
  the gateway client *read* a consumed module at `/v1/<as>/*`; nothing here
  decides that the prefix points there. `facade_claim_test.go` evaluates the
  package's constant string expressions and fails on any that is one of those
  wire shapes — folded, so a shape split across a concatenation, parenthesised,
  built from named constants or cased differently is the same shape to it.
- **Never sign, parse or verify a Work Context here.** There is one
  implementation, Core's; this runtime obtains a credential through the native broker
  client and delegates its structural read to Core, carries it as the string it travels as, and lets the far end
  decide. It declares none of a capability's fields and holds no verifier —
  core's needs the issuer's live revision, replay, grant and seal sources, which
  a solution does not have. `work_context_boundary_test.go` fails on a signing
  primitive, on a `WorkContext`-named declaration of this package's own, on a
  call to a verifier and on an import of core's generated wire types — the
  syntactic half. `typed_boundary_test.go` fails on **constructing** one of
  core's wire messages and on **decoding into** one, by RESOLVED TYPE: that is
  the escape the import and verifier rules cannot close, because
  `proto.Unmarshal(raw, &workcontext.SealedValues{})` needs no generated
  import, no signer and no verifier — `SealedValues` is a type *alias* for
  core's `WorkSealV1`, so the one SDK import this package already has is enough
  to allocate one and decode into it. The rule is on allocation and on decode
  DESTINATIONS rather than on the type appearing, because the type appears
  legitimately: `holdSealedIdentity` takes a `*SealedValues` and reads it
  through `GetInstallationId`. It keys on core's generated PACKAGE PATH rather
  than a set of message names, so an alias — the SDK's `Claims`, a
  function-local one, anything — resolves to the same type and a message core
  adds is covered the day it exists. This is not a style rule: a second signed encoding grew
  inside an SDK beside core's once, with its own payload struct, signer,
  verifier and error taxonomy, and 3,532 lines had to be deleted to get back to
  one. Every step of that was locally reasonable.
- The authority-bearing values are a narrower case still: the principal, the
  mint audience and the projected token's own audience are read **once**, through
  the SDK's authority reader, and frozen. The credential this process holds is
  sealed to the values it was minted under, so a value that resolves differently
  later is an error and never a reload — the reader rechecks them before every
  renewal, which is the one moment a drifted value would otherwise be laundered
  into a credential nobody approved. Do not add an ordinary accessor for one of
  those three.
  Most values also take an explicit env override, for an operator whose
  deployment the resolver cannot see — but an override is not how a
  *composition* supplies a value, because a Codefly render cannot set a bare
  environment variable on a service. Anything the composition has to supply is
  a declared workspace-configuration group read with `WorkspaceConfiguration` /
  `WorkspaceSecret` (`mcp/issuer-url`, `mcp/public-url`), and a refusal names
  that group/key, never a variable name.
- Validate at the boundary — boot, and the headers a request arrives with — not
  between internal callers. `validate()` is the model: each refusal names the
  variable or the provisioning path that fixes it.
- **The listener is plain HTTP on the resolved port, and the cell's mesh is
  what carries the hop.** Past the host's auth gateway every hop inside a cell
  is plaintext under istio ambient's ztunnel mTLS, the workload's identity is
  its ServiceAccount's SPIFFE ID — the mesh principal a presence document
  names, not an SVID this process presents — and TLS ends at the edge. So this
  listener presents no certificate and verifies no caller, and the mesh
  admits its port only from the gateway's principal. The previous generation
  served TLS 1.3 under a projected X.509-SVID, verified callers against a
  projected anchor, admitted them by three provisioned peer files, re-verified
  every established connection once a second in both directions and refused
  session resumption; `identity.go` and all of it are **deleted, not fenced**,
  because every one of those checks was this process re-deciding what the
  cell decides for every workload. If you are about to add a check on who is
  on the other end of a connection, you are rebuilding what this cutover
  removed; what this process still decides is what a caller may do once
  admitted (the stamped identity headers, this execution's credential) and
  where its own credentials may travel (below).
- **A plaintext destination is admitted only where the mesh is, by the SDK's
  rule and never by a copy of it.** The gateway URL — and the mint derived on
  it — goes through `workcontext.AdmitEndpoint`: `https` to any host; `http`
  to a loopback host on a local run, or to an in-cluster Service address
  (`<svc>.<ns>.svc[.<domain>]`) when the composition asserts
  `internal-transport/mesh-protected=true`; anything else is `ErrInvalid`
  naming the rule. It is the rule the composed modules apply to their own
  gateway value, and `validate()` and `newBrokerCredentialSource` both call
  it rather than restating it. The assertion is read ONCE, in `loadConfig`,
  into `meshTransport`, and answered from that snapshot wherever the rule
  asks — because every environment read sits in `loadConfig`'s call tree, and
  a configuration value is fixed at process start anyway. The snapshot keeps
  the SDK's three answers three (unset, set to a value, unreadable) and never
  trims the value: only the literal `true` asserts, and a misspelled
  assertion is a refusal rather than either answer. Do not add a boolean
  beside it; a per-service opt-in is what an address never has to qualify for.
- Workload credentials are acquired only for actual authority-consuming work,
  after the declared ceiling is checked. Boot, health, viewer-only routes, MCP
  handshakes and installation acknowledgements never mint. Authority-free
  declarations need no broker credentials. Each organisation/installation has
  independent acquisition, expiry and refusal state; no global credential.
- **Credential-bearing traffic never follows a redirect and never leaves the
  gateway's origin.** Go copies a request's headers onto a redirected one and
  strips only `Authorization`, `WWW-Authenticate` and `Cookie`, a 307 re-sends
  the body, and this runtime sets the bearer per round trip — so a client that
  merely inherits a transport, as every gateway client once did, hands a `307
  Location: http://…` the viewer's bearer, their capability and this workload's
  credential in cleartext. Build clients through `Gateway.platformClient`, which
  carries `ErrUseLastResponse`, and leave the transport's origin pin in place.
- **Authentication is the mesh's; what is still this process's is which
  stamped identity a request carries.** `x-org-id`, `x-session-id` and
  `x-codefly-installation-id` are read as the gateway stamped them from
  verified claims, and a request reaching this port came through the gateway
  or the mesh would not have carried it. The admitted-caller file this
  runtime once read per handshake, and the two per-destination peer files for
  the mint and the gateway, are gone: `ALLOWED_CALLERS_FILE`,
  `MINT_PEERS_FILE` and `GATEWAY_PEERS_FILE` admitted identities the mesh now
  admits at L4 from the edges the CLI delivers, and a second set here would be
  a second answer. The runtime dials exactly one origin, the gateway's
  workload endpoint, and `originPinned` refuses every other destination.
- **Every mint names the installation it acts under, and it comes from the
  header the gateway stamps.** The host requires it (core's
  `StartInput.InstallationID`) and refuses a mint naming none; an organization
  is not an installation, since one org may hold several.
  `x-codefly-installation-id` is the source, on the same footing as `x-org-id`
  and `x-session-id`: the gateway stamps all three from verified claims and
  replaces whatever a caller sent. A request naming none is refused, and not as
  a `ClientError` — no caller can stamp one, so it is not theirs to fix.
  **This paragraph said the opposite for two rounds.** It described reading the
  installation from the *seal* of the carried capability, with the header as a
  fallback, which is the SDK's rule for the direction where a capability IS the
  authority being carried — outbound, where `Attach` puts the seal's own
  installation beside it and the far end cross-checks the two. Inbound that
  carrier is caller-controlled: a browser can put a capability in
  `x-codefly-work-context`, and this runtime's standing property — with its own
  test, `TestBrowserSuppliedWorkContextIsNeverForwarded` — is that such a
  capability authenticates nothing. Reading the installation out of it would
  let a caller name the deployment their own mint is attributed to, and because
  `FromHeaders` refuses a capability whose installation carriers are
  incomplete, a caller sending a malformed one would decide whether the mint
  happens at all. The code has read only the stamped header since round ten;
  these two documents did not follow it, which is the failure this file warns
  about in its own first line.
  A background or delegated call would take the installation from the parent
  capability's seal on the held credential; no such path exists here, because
  every mint is viewer-driven and `ForModule` refuses a caller without an org
  and a session.
- **Credentials remain scoped to their organisation and installation.** The
  broker selects live consent from the organisation request; its response must
  match both host-stamped identifiers. Renewals within a scope retain its
  installation, digest and build incarnation. Across scopes and scope eviction,
  the process retains the same digest and incarnation. A mismatch refuses that
  work; it never adopts another execution or shuts down unrelated installations.
- Every `ForModule` path, including HTTP and MCP, uses `gatewayFor` to carry
  the declared ceiling and the host-stamped organisation/installation into
  acquisition. Plain route entry is not a request for module authority. Keep
  incoming identity validation and error sanitization at their boundaries.
- **What a composition supplies is declared configuration, and a published URL
  is held to what a dialled one is.** A Codefly render cannot set a bare
  environment variable on a service, so anything the composition owns is a
  workspace-configuration group read through the SDK (`mcp/issuer-url`,
  `mcp/public-url`) and a refusal names that group/key. In a deployed runtime
  context the MCP resource identifier must be **declared, not derived**: the
  derivation builds `<PUBLIC_URL>/solutions/<id>/mcp`, which is this runtime
  encoding the route the *host* serves it on — the assumption the Module
  Federation manifest URL was changed to stop making, for the same reason. A
  derived value satisfied the older "a public URL is set" check, so nothing
  refused it in the one case that mattered. Both MCP URLs are refused for
  userinfo, a query, a fragment, and plaintext in a deployment, and those
  refusals redact: the pairing refusal printed an identifier's `?token=` into
  the boot log.
- **Nothing mints per request.** One credential per organisation/installation plus renewals
  its own expiry dictates, and that has to survive the checks added in front of
  it: a route gate that asked the source on every viewer request turned a
  503-ing issuer into one audited mint per request, which is worse than the
  heartbeat this runtime deleted, because the heartbeat at least minted on a
  timer. Acquisition is single-flight with a backoff, a credential already in
  hand and unexpired serves while the issuer is unavailable, and a terminal
  answer is recorded **where the answer lands** rather than by whichever caller
  was still waiting — the ask is detached, so it can finish with nobody
  listening.
- **Nothing is reported with the mint, and the frontend is declared in one
  file.** `upstream` (the advertised origin) and `manifest` (the frontend
  manifest) travelled in the mint body for one generation and are deleted:
  the gateway resolves this solution's address from the delivered presence
  document's endpoints, through the SDK, from the carrier the CLI hands it —
  as for a module — and the frontend travels in the same document. The CLI
  reads it from `solution.frontend.codefly.yaml` beside the backend's
  `service.codefly.yaml`, the same file this runtime embeds
  (`Manifest.Frontend`, `go:embed`) and serves its manifest from
  (`frontend.go`): two readers of one file cannot disagree, where a Go field
  beside a file could. Its keys are core's `frontend` block field for field,
  every scalar declared because core refuses an omitted one, the dashboard
  held to the JSON object core carries (a mapping, string keys, no fraction,
  64 KiB encoded) and surfaces carried whole (`contract`, `applies`, `events`
  included). A boot without the file is refused naming it. Do not add a Go
  field for anything the host lists a solution under, and do not report
  anything about this process to the host: a process cannot declare what the
  composition did not.
- The install endpoint acts under the host's incoming installation capability.
  Its acknowledgement never acquires workload authority. HTTP 412 means a
  failed precondition, not a unique "installed nowhere" state. Later actual
  work may retry after bounded backoff; no startup/idle/install polling loop.
- **The execution mint follows the host's module broker contract natively,
  over plain HTTP to the gateway's workload endpoint.**
  `saas-sdk-go/moduleauthority.MintModuleWorkContext` owns the broker wire
  protocol. Supply `prefix: Manifest.ID` and the host-stamped organisation to
  `/modules/_work-context`, with
  the projected token as bearer and `X-Codefly-Internal-Token` from the
  declared workspace secret `module-authority/INTERNAL_TOKEN` — kept: the
  host's waiver of that header on its workload peer existed only because the
  SVID authenticated the peer, and with the SVID gone the waiver goes too.
  Resolve the secret in `loadConfig`, refuse absence in `validate()`, and
  never resurrect a legacy secret reader. The projection audience is
  `accounts`; the prefix never replaces the frozen SPIFFE principal. The mint
  URL is the host's published route on the gateway this process already
  resolved: the workload endpoint serves the gateway's whole handler, so there
  is no second address to resolve and `CODEFLY__CREDENTIAL_MINT_URL` is gone.
  The native transport owns one plain-HTTP request per mint on a connection
  dialled for it, pinned to that origin, with redirects, proxies and reuse
  disabled, and the URL held to the SDK's transport rule before anything is
  sent; an `https` gateway is verified against the system roots, the right
  anchor for an edge that presents a public certificate. The SDK still owns
  the authority reader. `workcontext.MintClient` is NOT the production mint
  client and must not become one without the host serving its wire shape: it
  posts `{audience, projection_audience}` and reads `{work_context}`, where
  the host takes `{prefix, organization_id}` and answers `{token, expiresAt, principalId,
  tenant}`; this runtime replaced it with the native client in #59 for that
  reason, and the two places that still construct one — `credential_test.go`
  and `passthroughtest` — do so against fakes that speak the SDK's shape, which
  is a finding for the audit and not something a deployment exercises. Core's
  `Decode` is the only structural reader of the returned token; no signed
  message is constructed or decoded here, and that read verifies no signature.
  It was `Inspect` until core v0.15, and the old name is now core's
  `Inspector` — a forwarding hop's **signature check** — so it is a verifier to
  this package and the verifier gate refuses it, with `Authenticator`, by name.
  A private credential view keeps the public SDK `CredentialSource` compatible.
- Refusals are scoped. Each controller retains the answer even if all waiters
  leave, backs off, and never uses held authority after refusal or expiry.
  Later work may recreate a refused scope after backoff to observe changed
  consent. A failure never stops other installations or the shared listener.
  Keep safe status/class/category, never bodies, parser messages or causes.
  Missing projection, 412, 503 and transient transport failures are unavailable;
  frozen authority and execution consistency still fail closed on every ask.
- Bound retained scopes (256), waiters (cancellation/500ms), acquisition lifetime,
  and detached projection reads. Never evict a scope with active work/acquisition.
  The server shares the projection read slot across scopes so eviction cannot
  accumulate blocked file reads. Do not let one caller cancel shared acquisition.
- A module's 409 does not prove workload revocation. The host must provide a
  machine-readable discriminator before the runtime may infer supersession.
- **Fail closed, with no exception for a counterpart's current state.** A mint
  this runtime cannot attest for is not sent; a credential-bearing destination
  outside the SDK's admitted transport rule is refused at boot. "The gateway presents no client
  certificate today" and "the host does not require the attestation yet" are
  statements about someone else's deployment, and leaving a hole open for as long
  as the counterpart takes is the concession this cutover exists to stop making.
- The published contract is **declared, not derived**. A scope ceiling computed
  from what the code asks for would be satisfied by construction — a method that
  asked for one more action would widen the ceiling meant to refuse it — so the
  author declares the ceiling per profile, the boot refuses a declaration that
  exceeds it, and a deployed profile missing from the contract is a refusal
  rather than a silent read of the local one.
- **The contract this runtime publishes is not the one the renderer reads, and
  must never claim its schema string.** The renderer reads exactly one file,
  `module.contract.codefly.yaml` — YAML, strict-decoded, at the module directory
  the composition resolved — under `codefly/module-contract/v1`, whose audiences
  are `{from: <group>/<key>}` slots a composition resolves per environment
  (`codefly-dev/cli#855`); it never reads a running process or a build artifact.
  This runtime publishes JSON, keyed by profile, under its own
  `codefly/solution-runtime-contract/v1`, answering what a process holds *itself*
  to. Both surfaces claimed the renderer's string once, which is worse than a
  mismatch: strict decoding refuses the unknown fields, and a matching string
  makes that a *malformed* module contract rather than somebody else's document —
  a version skew that is not one, pointing at the wrong owner.
  `TestThisRuntimesContractDoesNotClaimTheRenderersSchema` fails if the two ever
  converge again. Writing the renderer's file would be a generator in this repo
  and nothing here does it today.
- **The MCP surface verifies no token, and must not start.** The gateway runs
  ext_authz and stamps the identity, so a check here would be a second,
  divergent copy of the host's admission rules. What `requireStampedViewer`
  enforces is that the gateway did it, and the refusal for a credential with no
  session is at that boundary rather than inside a tool, where it would read as
  a broken tool. A tool's arguments are written by a model: no identity ever
  comes from them.
- Tests live beside the code in the same package. Every behaviour change brings
  one, and the counterpart it exercises is an `httptest` server, never a real
  host.

## How to behave when something does not work

Fleet standard. These are not style preferences; each is a rule an agent broke
at real cost, and this repository is the runtime that cost was measured
against.

1. **A gap in the tooling is a bug in the tooling** — never a reason to reach
   around it. Not as a "workaround", not "just this once", not "until the verb
   lands". The failure that produced this standard was exactly that: unable to
   run three solutions under one `codefly run`, an agent hand-wrote the
   environment these runtimes exist to resolve — internal token, endpoint
   carriers, credential paths, pinned ports. It worked, and a sibling runtime
   with a missing credential skipped registration *silently*, so a solution
   booted, served, and was simply absent. The real cause was a missing CLI
   capability (codefly-dev/cli#717). If the CLI cannot express a composition,
   that is a CLI bug; if the SDK cannot resolve a value, that is an SDK bug.
   Neither is a reason to add a default here. The env overrides in the README
   exist for an operator with a deployment the resolver cannot see — they are
   not a way to fill a gap in resolution.
2. **Never hack. Always provide the best fix, even when it spans repos.**
   Almost nothing that breaks here is owned here. Resolving the host by service
   role rather than by module name needed a change in `codefly-dev/core`
   (core#382); loading a composed module's workspace path needed another
   (core#365). Both were fixed at the owner and arrived here as a `go.mod` pin —
   which is why this module carries no `replace` directive. The right fix living
   in someone else's repo is not a reason to work around it in this one. If it
   genuinely cannot be fixed now, the deliverable is a precise issue against that
   owner plus an explicitly labelled stopgap, never an unlabelled one.
3. **Classify every change that makes something work**, in the PR body: a *fix*
   at the place that owns the behaviour, or a *hack*. A hack does not become a
   fix by working, by being small, by being local, or by the real fix belonging
   to core, the SDK or the host.
4. **Never hardcode what the system resolves, and never guess what it cannot.**
   This package resolves every address, port and secret through the SDK, and
   carries no address literal at all: the `localhost` the advertised-origin
   fallback used went with the report it fed. The credential mint URL is the
   one derived value, and it is derived from a published fact rather than a
   guess: the gateway's workload endpoint serves the gateway's whole handler,
   mint included, so the mint is `/modules/_work-context` on the one origin the
   composition resolved. That is a different thing from the derivation this
   rule used to forbid — a path assumed on the public gateway while the host
   served its mint somewhere nobody had published, carried for two rounds as a
   "labelled stopgap" — and the test that pinned its absence
   (`TestNoProductionCodeDerivesTheMintAddress`) was replaced by one that pins
   the published route. If the host moves the mint off the workload endpoint,
   the fix is a resolved endpoint role, not an override.
   If you are typing an address, a port or a credential, you are encoding
   something true only on your machine for the next ten minutes; if you are
   deriving one the owner has not published, you are encoding a guess about
   somebody else's deployment.
   The MCP resource identifier is derived the same way — from the resolved
   `PUBLIC_URL` and the solution id — and is the one place the gateway's
   `/solutions/<id>` route is encoded here. `PUBLIC_URL` itself went with the
   manifest registration it fed and came back for this one consumer: whether a
   runtime should derive the host's route at all is an open follow-up, not a
   settled answer.
5. **Diagnose, do not pattern-match.** "It started working when I set X" is not
   a diagnosis — set X back and confirm it breaks. Do not trust an error message
   before checking it: in the session above, *"the provisioned secret does not
   match its digest"* actually meant a missing internal token. `validate()`
   already carries that lesson — it separates "the SDK resolved nothing" from
   "loading the injected environment failed first" from "your own override
   cannot be paired", because the single generic message sent an operator to
   inspect endpoint resolution over a variable they had broken themselves. Keep
   new refusals that specific.
6. **Say what you did not verify.** Unverified is not the same as working, and
   this suite makes that easy to get wrong: it is hermetic. Every host, gateway
   and accounts counterpart is an `httptest` server on `127.0.0.1`, so a green
   run proves the wire shapes and refusals this package produces — never that a
   real host admits a registration, that accounts mints a Work Context, or that
   a composed module accepts one. If you did not run it against a real
   composition, the PR says so.

7. **Prove reuse before you build.** The default answer is that the platform
   already has it and your change fills a gap or adds a helper on it, so the PR
   body names what you reused and what you deliberately did not. A second
   mechanism for a job one seam already does is refused however clean it is.
   Two tells you are reinventing: what you are writing re-answers a question an
   existing seam answered, and your reason for its placement is that a
   convenient loop was already there rather than that the responsibility
   belongs to it.

8. **Build the simplest thing that works; size is the signal.** A coding task's
   budget is about **500 hand-written lines** — generated output does not
   count, tests count apart — and past **2,000** the change has become a second
   system, so **stop and ask the user** instead of finishing it. Two tells,
   checkable before the code exists: you cannot name the one responsibility the
   change adds, and it is growing to make the end goal pass rather than to put
   a behaviour where it belongs. Wanting it to work licenses no means to get
   there.

## Build and test

Derived from [`.github/workflows/go.yml`](.github/workflows/go.yml), the only
gate. It is four commands, and they are the whole local loop:

```sh
go mod download && go mod verify
go test -race ./... -count=1 -timeout=5m
go vet ./...
test -z "$(gofmt -l .)"
```

Go comes from `go.mod` (1.27). Nothing else is needed: no Docker, no
credentials, no running composition.

- The suite takes about a minute under `-race` and is hermetic: the host's mint, its gateway
  and accounts are all `httptest` servers on `127.0.0.1`, the workload identity
  is a key pair the test generates into a temp directory, and a stand-in
  capability is minted by **core's** authority from core's published fixture
  identities — never by a signer of this repo's own. The two
  heartbeat tests that waited on 10s and 5s of real wall time are gone with the
  heartbeat.
- The formatting gate runs over the whole tree (`gofmt -l .`), so a package
  added in a subdirectory is format-checked as well as vetted and tested.
- Dependency pins are how fixes from `core` and `sdk-go` reach consumers:
  `go get github.com/codefly-dev/core@vX.Y.Z && go mod tidy`, then the four
  commands above. `go mod tidy` is a no-op on a clean tree, so a diff it
  produces is part of your change. Say in the commit *why* the pin moves and
  reference the owning issue — "bump" is not a reason.
- Releases are plain `vX.Y.Z` tags on `main`; there is no release workflow, and
  the one GitHub Release object (v0.0.2) was not kept up — it names no current
  version and nothing reads it. The tag is what consumers pin, so it is cut
  from a commit whose gate is green.

## Where the depth is

Keep this file short; add depth to the file that owns the subject.

- [README.md](README.md) — the consumer-facing contract: handler errors, the
  full configuration and env-override table, plain HTTP inside the cell, the
  declared frontend file and the one mint, the published contract,
  consumed-module federation, and reading a
  Work-Context-authenticated module. It also carries the migration note: an old
  runtime against a new host gets 404, and nothing bridges the two.
- The package doc comment and the comments in [`solution.go`](solution.go),
  [`credential.go`](credential.go), [`frontend.go`](frontend.go) and
  [`contract.go`](contract.go) and [`mcp.go`](mcp.go) — why a refusal, a renewal point or a cache
  lifetime is what it is. Several record a failure mode that is not obvious from
  the code; read the one next to what you are changing before you change it.
- `.claude/skills/` — procedures an agent repeats, loaded only when relevant.
  None exist yet, because nothing here repeats beyond the four commands above.
  Add one instead of growing this file.

The optional frontend declaration uses Core's `solutionhost.ParseFrontend` and
its types directly. Nil is headless; a present malformed file refuses boot.
Do not introduce a second parser, size limits or a fixed client-kind inventory.
