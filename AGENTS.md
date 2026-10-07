# Working in solution-runtime-go

This repository owns the generic Go runtime for **codefly solutions** — modules
deployed independently of the host they extend, with no build-time coupling. It
owns what every solution needs identically: configuration resolution through the
codefly SDK, obtaining this execution's credential once from the projected
service-account token, a listener that presents the workload's own X.509-SVID,
CORS, Module Federation asset serving, the capability handshake, the manifest,
the published authority contract, serving the solution's MCP server to agent
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
gateway; the mint-once client, the authority reader and the TLS reloader to
`codefly-dev/sdk-go`; endpoint, port and secret resolution to `sdk-go` as well;
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
`validate()`, the mTLS boot, the caller allow-list, the ceiling and
authenticated outbound — with the viewer's bearer and this workload's own
credential on the wire, and supplying a credential source defeated the "no
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
  implementation, Core's; this runtime obtains a credential through the SDK's
  mint client, carries it as the string it travels as, and lets the far end
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
- The listener presents this workload's own identity and there is no plain-HTTP
  listener. A configuration that cannot produce one is refused at boot naming the
  material, because a solution serving plain HTTP is refused at the edge instead,
  for a reason only the edge can see. Where the identity comes from is the
  platform's: `IdentitySource` is the hook, and the default reads the pair the
  platform projects through the SDK's reloader. A source's configuration is
  checked for what it must *have* (a certificate, a TLS 1.3 floor,
  `RequireAndVerifyClientCert`, a named anchor) **and refused for what it must
  not replace**: `Time`, `Rand`, `KeyLogWriter`, `WrapSession`, `UnwrapSession`,
  `InsecureSkipVerify`. Each has a safe zero value, so refusing a non-zero one
  is exact — and resumption is the sharpest, because a resumed connection
  presents no certificate, so a source encoding its own tickets admits callers
  without any check here seeing a handshake. That list is a denylist over a
  struct this package does not own, and it is **not** complete. That claim was
  made here and falsified twice: first by the session-ticket keys, then by
  `VerifyPeerCertificate`. A `Clone()` copies 29 of 32 fields unchanged, so
  whatever this list does not name, a source keeps. Where a property is
  load-bearing, **take** it rather than check it — resumption is disabled
  outright, and a caller's identity is read from a fresh parse of the raw DER
  rather than from the `*x509.Certificate` a source's own verifier was handed a
  pointer to. This list is what *tells* a source it has gone wrong; it is not
  what makes the listener safe. The per-connection answer runs through the same
  function rather than a copy of its reasoning. `SessionTicketKey`
  is on that list for the same reason as the callbacks — choosing the key tickets
  are sealed with is the same capability as encoding them — and
  `SetSessionTicketKeys` is the one hole a check cannot close, because it is a
  method and the keys it installs cannot be read back off the configuration.
- **This listener does not resume TLS sessions, and that is a control rather
  than a check.** A resumed connection presents no certificate, so anything
  able to forge a ticket is admitted as whoever it was issued to — demonstrated
  end to end with a source-supplied ticket key, against a listener whose
  posture checks all passed. A denylist cannot close it (`SetSessionTicketKeys`
  installs keys that cannot be read back), so `SessionTicketsDisabled` is set on
  the served configuration and on every per-connection clone. Where a property
  cannot be verified on a value a consumer hands over, take it rather than
  inspect it.
- **A source's anchor is asked for, never fabricated.** A consumer source that
  resolves its anchor per handshake implements `PeerAnchorSource`; one that can
  only answer through a `GetConfigForClient` call is refused at boot, because
  obtaining the anchor would mean passing a `ClientHelloInfo` nobody sent — the
  same synthetic-probe defect this cutover was blocked on for certificates, and
  worse, since an anchor has no check behind it. The outbound *certificate* is
  still taken through an empty hello, which is sound only because the frozen
  principal hold catches a wrong answer at the moment it is presented.
- The credential is obtained **once**, before the listener exists. A *refusal*
  fails the boot and is never retried — the host is saying this build is not the
  one its presence document approved, which no number of attempts changes, and a
  loop around it is the audited-mint cost this runtime was changed to remove. An
  *unavailable* mint is not a judgement (a presence generation not yet applied,
  an issuer that cannot reach its own dependencies), so the boot waits inside a
  bounded window, with the window as a deadline on the operation, and then exits
  non-zero for the orchestrator. Those two answers must stay distinguishable:
  conflating them was a review blocker in both directions.
- **Credential-bearing traffic never follows a redirect and never leaves the
  gateway's origin.** Go copies a request's headers onto a redirected one and
  strips only `Authorization`, `WWW-Authenticate` and `Cookie`, a 307 re-sends
  the body, and this runtime sets the bearer per round trip — so a client that
  merely inherits a transport, as every gateway client once did, hands a `307
  Location: http://…` the viewer's bearer, their capability and this workload's
  credential in cleartext. Build clients through `Gateway.platformClient`, which
  carries `ErrUseLastResponse`, and leave the transport's origin pin in place.
- **Peer trust is re-read per connection in BOTH directions, and established
  connections are re-verified.** Inbound, per handshake through
  `GetConfigForClient`; outbound, per dial through `DialTLSContext`. Per-dial
  and per-handshake bound nothing about a connection that already exists, which
  an idle timeout cannot fix because it only bounds a connection nobody is
  using: a busy outbound connection answered 31s after its root was removed, and
  the listener had no recheck, no `IdleTimeout` and no `ReadHeaderTimeout` at
  all. Both directions now re-verify the established peer against current trust
  once a second and close what stops verifying. The recheck reads only the
  anchor and the admitted set — never this workload's own leaf, so a
  half-written rotation of our own key pair cannot tear down connections whose
  peers are fine — and the outbound leaf comes from ONE long-lived SDK reloader,
  which keeps the last good pair; building one per dial threw that away. The outbound half went
  unanswered through two review rounds while the inbound argument — judging by
  a stale anchor admits whoever should be refused — was already written down
  here. It applies harder outbound: those destinations receive the projected
  token, the viewer's bearer and this workload's credential.
- **Authentication is not authorisation.** Every workload in the trust domain
  holds a certificate from the same anchor, the consumed modules included, so
  the admitted caller set is provisioned
  (`workload-identity`/`ALLOWED_CALLERS_FILE`) and refused at boot when absent.
  Outbound there is **one set per destination** (`MINT_PEERS_FILE`,
  `GATEWAY_PEERS_FILE`): the mint and the gateway are two parties, and a single
  set spanning both authorises each to stand in for the other at the other's
  address — the mint being the one that receives the projected token.
  `MINT_PEERS_FILE` governs the mint hop again, per handshake, through the
  SDK's `AdmittedPeers` reader (sdk-go#51) — so the question it was kept open
  for is settled: it is the authorization set for the destination that receives
  the projected service-account token. It also still narrows the shared-address
  case, where the mint and the gateway answer at one address and a dial cannot
  be attributed, and what is admitted there is the intersection of both sets. A dial to
  a third address has no set and is refused, because this runtime talks to
  exactly two destinations.
  An admission set answered by **both** the env override and the platform's
  provisioning is refused rather than ranked — two sources for one
  authorization fact, which is the stance the SDK already takes on a value
  delivered inline and by carrier. The other paths in that group still take the
  override first, because the worst case there is this process reading its own
  material from somewhere else, not admitting a caller.
  Both admission sets are **paths this process reads itself**, per handshake and
  per dial, not configuration values: a value is fixed at process start, so
  "re-resolved per handshake" through the SDK's accessor returned the boot answer
  forever while the code and the README both said revocation needed no restart.
  Anything in `workload-identity` the platform can change is a path or it is a
  snapshot pretending otherwise. A
  listener that verifies every caller and admits all of them lets a consumed
  module set its own `x-org-id`/`x-session-id` and drive mints under this
  workload's attestation.
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
- **This execution's own credential is held to what it was FIRST sealed to.**
  The host seals it from the projected token — `MintOptions` carries no
  installation field — so what this runtime owns is refusing one sealed to no
  installation, refusing one sealed to no **execution** (image digest and build
  incarnation, which core seals as a pair), and refusing a renewal sealed to a
  *different* installation, digest or incarnation. The last is one value, not
  three checks: a renewal that changed any part of it is a different
  execution's credential arriving through the renewal path, and every work
  context this process mints for a viewer is attested by it — so the mints
  either side would name a different deployment or a different build,
  including one the host's approved-build ceiling was never applied to. The
  no-execution case is the one the sdk-go v0.3.0 migration opened: the previous
  SDK's reader refused a zero incarnation, so a credential arriving here
  carried one by construction, and core legitimately mints execution-free
  credentials for a principal recorded as bearing none. The guarantee was
  inherited and the inheritance ended.
- **Every surface that acts for a viewer is held to this execution's
  credential, and the MCP methods are held by an allowlist.** A plain handler
  and a `ViewerBearer` passthrough were gated and a tool call was not, so an
  MCP tool received a gateway carrying the viewer's bearer and ran while the
  issuer had withdrawn this process's credential — the same fail-closed defect,
  arriving with a surface rather than being missed in one. `actsForNobody`
  lists the methods that run nothing for anyone (the handshake, the keepalive,
  the listings, notifications) and **everything else** goes through
  `actingForAViewer`: a method the MCP SDK adds is gated by default, because a
  denylist over a set this package does not own is the mistake the TLS posture
  made three times. The refusal carries the sanitized sentence, never the
  source's error — an MCP client is a viewer's channel like a browser is. It
  carries a JSON-RPC code, `-32001`: this file said the SDK's wire-error type
  was internal and that no code could be set, which was false —
  `jsonrpc.Error` is an exported alias for it, mutant `R10-8` holds the code,
  and the claim survived here for two rounds after the code landed.
- **What a composition supplies is declared configuration, and a published URL
  is held to what a dialled one is.** A Codefly render cannot set a bare
  environment variable on a service, so anything the composition owns is a
  workspace-configuration group read through the SDK (`mcp/issuer-url`,
  `mcp/public-url`) and a refusal names that group/key. In a deployed runtime
  context the MCP resource identifier must be **declared, not derived**: the
  derivation builds `<PUBLIC_URL>/api/solutions/<id>/proxy/mcp`, which is this
  runtime encoding the route the *host* serves it on — the assumption the Module
  Federation manifest URL was changed to stop making, for the same reason. A
  derived value satisfied the older "a public URL is set" check, so nothing
  refused it in the one case that mattered. Both MCP URLs are refused for
  userinfo, a query, a fragment, and plaintext in a deployment, and those
  refusals redact: the pairing refusal printed an identifier's `?token=` into
  the boot log.
- **Nothing mints per request.** One credential per execution plus the renewals
  its own expiry dictates, and that has to survive the checks added in front of
  it: a route gate that asked the source on every viewer request turned a
  503-ing issuer into one audited mint per request, which is worse than the
  heartbeat this runtime deleted, because the heartbeat at least minted on a
  timer. Acquisition is single-flight with a backoff, a credential already in
  hand and unexpired serves while the issuer is unavailable, and a terminal
  answer is recorded **where the answer lands** rather than by whichever caller
  was still waiting — the ask is detached, so it can finish with nobody
  listening.
- **The mint hop is held to the same three things the gateway hop is, and the
  SDK owns the transport that holds it.** `MintOptions` takes no pool, no
  client and no dialler: it takes `TrustAnchor`, `ClientCertificate` and
  `AdmittedPeers` as **readers**, each consulted during the handshake
  (sdk-go#51). So the mint request presents this workload's X.509-SVID, the
  endpoint is admitted by the SPIFFE ID in its single URI SAN against
  `MINT_PEERS_FILE`, and the anchor is re-read before and after every
  handshake and never cached. Withdrawal of a root or of a peer takes effect on
  the next handshake rather than on the next process.
  The SDK still refuses a caller-supplied `*http.Client`, and that reasoning is
  sound and worth keeping in mind: a supplied client is a hole it cannot
  inspect — a nil `Transport` means the global mutable default, a
  `DialTLSContext` bypasses `TLSClientConfig` entirely, and a caller holding
  the same `*http.Transport` can turn verification off after construction. The
  answer was never for this runtime to take the transport back; it was for the
  transport to take readers instead of values, which is what it now does.
  **This paragraph said the opposite, and said it was unreachable.** It
  recorded that the mint presented no certificate, that `MINT_PEERS_FILE` did
  not govern that hop, and that the rest of the posture could not be restored
  from outside the SDK — accurate at `v0.3.0`, and the reason it was an sdk-go
  issue rather than a local workaround. What was wrong was not the diagnosis
  but treating the resulting gap as a property of this runtime: a reviewer
  pointed out that the fixtures had been weakened to accommodate it
  (`VerifyClientCertIfGiven`, the mint caller's identity expected to be empty),
  which establishes a changed behaviour rather than closing a finding. The
  fixtures demand the certificate again, and
  `TestTheMintHopIsHeldToTheSameThingsTheGatewayHopIs` drives the negative
  controls through a real handshake: a peer the anchor signed but the set does
  not name, peer withdrawal with the anchor unchanged, an unreadable anchor,
  and a certificate reader that cannot answer.
  **There is no established mint connection to bound, and this file said there
  was.** It recorded a residual — "the client keeps idle connections, so a
  withdrawal takes effect on the next handshake and not on a connection already
  open" — which was true of `v0.3.0` and is not true of the pinned leaf. That
  transport sets `DisableKeepAlives`, `MaxIdleConnsPerHost: 0` and
  `ForceAttemptHTTP2: false`, so **every mint is a fresh handshake**; and after
  the handshake completes it re-reads the anchor and the peer set and verifies
  the peer again, because `GetClientCertificate` and the server's own
  processing run *after* the first admission decision and a withdrawal landing
  in that window must not authorize the HTTP write. It also refuses an endpoint
  that did not request a client certificate, so this hop cannot silently become
  anonymous. The residual to carry is narrower and belongs to the SDK: the
  interval between that post-handshake recheck and the write itself.
- **Only 401 and 403 latch a credential refusal.** The rule was "429 and 5xx
  retry, everything else is terminal", and sdk-go v0.3.0 inverted it after
  measuring the cost: a 408 from a proxy, with a valid credential in hand,
  refused and latched for the life of the process, and a 404 from an ingress
  mid-rollout would do the same. Those two are the statuses the host signs —
  the projected token is not acceptable, or the build is not approved. **A 404
  on the mint is now an outage**, so an old runtime against a host of this
  generation waits out its bounded window and exits non-zero for the
  orchestrator rather than failing on the first answer. It still does not
  recover; what changed is the shape, not the outcome.
- **A terminal credential refusal ends the process; a transient one does not.**
  `ErrMintRefused` at renewal fails `/health` and ends `serve` with the reason.
  `ErrMintUnavailable` must not: it is transient by construction and exiting on
  it is a crash loop. `ErrRevoked` is not in either set, and three review rounds
  found this file still saying it was: the mint client does not return it at all
  (see `credential.go`) — it comes back from a *callee* rejecting a capability
  this runtime minted for a viewer, where it is a 409 on that request and no
  statement about this execution's own credential.
  **Nothing is inferred from that 409, and the code now matches what this file
  has said all along.** A cached capability was dropped when a module answered
  409 with an installation header, and that was wrong three times over: any 409
  with any header; then any 409 whose header named the installation the
  capability is sealed to — and a module answering an ordinary business
  conflict IS in that installation, so a duplicate or a lost update evicted a
  valid capability and the next call minted again. 409 means "the state you
  were sealed to has moved" and it means "that page already exists"; nothing on
  the wire says which, and matching installation metadata identifies the SCOPE
  of a conflict rather than establishing supersession. A genuinely superseded
  capability is refused call by call by the far end, correct if noisy, until its
  own expiry. A sound inference needs a host-side discriminator, which is
  nobody's to invent here. The boot and the run have to
  classify these the same way — they did not, and the result was a solution
  answering 503 forever while reporting itself healthy.
- **Fail closed, with no exception for a counterpart's current state.** A mint
  this runtime cannot attest for is not sent; a listener that cannot
  authenticate its callers does not start; a credential-bearing destination that
  is not authenticated https is refused at boot. "The gateway presents no client
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
   This package resolves every address, port and secret through the SDK; the
   single `localhost` literal in it is the self upstream's listen-address
   fallback, built from the *resolved* port and refused by `validate()` in a
   deployed runtime context. The credential mint URL has **no default**: it is
   the address the projected service-account token goes to, nothing resolves it
   yet, and a derived path on the resolved gateway was carried for two rounds as
   a "labelled stopgap" while the README described it as settled — a guess a
   label does not make safe. It is refused at boot until something resolves it.
   If you are typing an address, a port or a credential, you are encoding
   something true only on your machine for the next ten minutes; if you are
   deriving one the owner has not published, you are encoding a guess about
   somebody else's deployment.
   The MCP resource identifier is derived the same way — from the resolved
   `PUBLIC_URL` and the solution id — and is the one place a route of the host's
   is encoded here: its **public** proxy route, `/api/solutions/<id>/proxy`, not
   the gateway's in-cluster `/solutions/<id>`, which on the public origin is a
   page of the host's frontend. It derived and *suggested* the in-cluster one,
   and a suggestion is the worse half — an operator reads it as the answer.
   `TestMCPIdentifierNamesTheHostsPublicProxyRoute` pins the constants against a
   literal, which keeps anyone from changing them here unnoticed and cannot do
   more: nothing in this suite can see the host, so a host that changes its route
   leaves this repository green and breaks a client's discovery, with no
   automated alarm for that case today: the test for it must compare the host's
   own rendered route against the identifier this runtime advertises, so it
   belongs where the host is visible, in module-saas-starter. What limits that
   is the deployed refusal, not a test — a deployment declares the identifier,
   so no cell depends on these constants. A declared one
   is published verbatim for the same code-point reason, so a trailing slash is a
   different identifier and is refused, not trimmed. A loopback or unspecified
   address is refused by classifying what a URL consumer reads after UTS-46
   mapping and the subset of WHATWG's host rules that decides what a host is,
   not by matching notations. A host is one of exactly three things — an
   address, a name, or neither — and the third is a refusal naming the
   provisioning key, never a fallback to the second; both published URLs go
   through the one function that decides it. Mapping a host successfully is not
   the same as the host being usable, which is how the name branch was the soft
   one twice: it now checks label boundaries and DNS lengths as well, without
   tightening what the mapping allows on purpose (an underscore, a leading
   digit, one rooted dot). A *name* that merely resolves to
   loopback is not refused, because that needs a lookup this runtime does not
   do at boot. `PUBLIC_URL` itself went with the manifest
   registration it fed and came back for this one consumer: whether a runtime
   should derive the host's route at all is an open follow-up, not a settled
   answer.
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
  full configuration and env-override table, the workload identity and the one
  mint, the published contract, consumed-module federation, and reading a
  Work-Context-authenticated module. It also carries the migration note: an old
  runtime against a new host gets 404, and nothing bridges the two.
- The package doc comment and the comments in [`solution.go`](solution.go),
  [`credential.go`](credential.go), [`identity.go`](identity.go) and
  [`contract.go`](contract.go) and [`mcp.go`](mcp.go) — why a refusal, a renewal point or a cache
  lifetime is what it is. Several record a failure mode that is not obvious from
  the code; read the one next to what you are changing before you change it.
- `.claude/skills/` — procedures an agent repeats, loaded only when relevant.
  None exist yet, because nothing here repeats beyond the four commands above.
  Add one instead of growing this file.
