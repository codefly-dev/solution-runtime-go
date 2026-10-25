# Working in solution-runtime-go

This repository owns the generic Go runtime for **codefly solutions** — modules
deployed independently of the host they extend, with no build-time coupling. It
owns what every solution needs identically: configuration resolution through the
codefly SDK, a plain-HTTP listener on the port Codefly resolves — the cell's
mesh carries transport security and destination identity for every hop inside
it — CORS, Module Federation asset serving, the capability handshake, the
manifest served from the one declared frontend file, the published contract,
the connection to the **authority interface** (who each request is for, and
every Work Context the solution acts under), the passthrough that relays a
page's module calls as the viewer, and serving the solution's MCP server to
agent clients.

**The runtime runs only under the authority.** The saas-host mode — a bearer
forwarded to the host's gateway, `ForModule` minting a Task Work Context
through accounts, the broker execution credential, `Transcoded`/`Unary`
calls over a module's REST binding, the install step, gateway-stamped
identity headers and the MCP surface's OAuth discovery against the host's
issuer — is **deleted, not fenced**. A boot whose composition names no
`authority/endpoint` is refused. If you are about to add a path that reaches a
module, or learns who a viewer is, without the authority, you are rebuilding
what this repository deleted.

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

It owns none of the counterparts it talks to. Who a Work Context is for, what
a route requires and every issue belong to the authority
(`codefly-dev/authority`, whose client this runtime links); the one transport
rule that admits a plaintext URL (`workcontext.AdmitEndpoint`) and endpoint,
port and secret resolution to `codefly-dev/sdk-go`;
workspace, manifest and presence/authority document types to `codefly-dev/core`;
running a composition, provisioning its secrets and rendering the authority
document to `codefly-dev/cli`. Everything here is a library — one Go package at
the repository root, consumed as the Go module
`github.com/codefly-dev/solution-runtime-go` at a `vX.Y.Z` tag.

**No exported path hands out the passthrough's handler.**
`Server.PassthroughHandler` was exported, and a deployment calling it completed
a viewer mint and a module call over plaintext, 200, having skipped
`validate()` and the boot. The
passthrough is mounted by `serve` alone, under the authority. The saas-host
test seam that replaced the export (`passthroughtest`, through `internal/seam`)
went with the saas passthrough it faked.

The handler-export, capability-decoder and seal-construction gates
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
  allocated by allocating the value. Expanding every carrier reported a holder
  of a credential source as constructing a capability, because its field is
  an interface whose method returns the SDK's credential, which is an alias
  for one of core's wire messages. A **decode
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
real condition being removed.

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
- Resolving a value in `loadConfig` is half the rule; the other half is a
  refusal in `validate()` that fires **whether or not the feature using it is
  switched on**, and a value nothing consumes is not read at all. The
  `api.consumes` projection was decoded and judged here only for the saas
  passthrough's agreement check; the authority's relay reads its address and
  binding from the slots each module's declaration names, so the projection is
  no longer read.
- A solution claims no module's facade route and holds no credential that would
  let it: a route for a module is claimed by the module that serves it, under a
  credential bound to that module (#51, SA-F-GWREGISTRY). `facade_claim_test.go` evaluates the
  package's constant string expressions and fails on any that is one of those
  wire shapes — folded, so a shape split across a concatenation, parenthesised,
  built from named constants or cased differently is the same shape to it.
- **Never sign, parse or verify a Work Context here.** There is one
  implementation, Core's; this runtime has the authority issue every Work
  Context it acts under, carries it as the string it travels as, and lets the
  far end decide. It declares none of a capability's fields and holds no verifier —
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
  legitimately: a seal read through the SDK's `GetInstallationId` accessor is
  not an allocation. It keys on core's generated PACKAGE PATH rather
  than a set of message names, so an alias — the SDK's `Claims`, a
  function-local one, anything — resolves to the same type and a message core
  adds is covered the day it exists. This is not a style rule: a second signed encoding grew
  inside an SDK beside core's once, with its own payload struct, signer,
  verifier and error taxonomy, and 3,532 lines had to be deleted to get back to
  one. Every step of that was locally reasonable.
- Anything the composition has to supply is a declared workspace-configuration
  value read with `WorkspaceConfiguration` (`authority/endpoint`,
  `hop/ENFORCEMENT`, each consumed module's relay slots), and a refusal names
  that group/key, never a variable name: a Codefly render cannot set a bare
  environment variable on a service. The env overrides that remain (`PORT`,
  `CODEFLY__WORKLOAD_TOKEN_FILE`, `CODEFLY__CONTRACT_PROFILE`, `ASSETS_DIR`)
  are for an operator whose deployment the resolver cannot see.
- Validate at the boundary — boot, and the headers a request arrives with — not
  between internal callers. `validate()` is the model: each refusal names the
  variable or the provisioning path that fixes it.
- **The listener is plain HTTP on the resolved port, and the cell's mesh is
  what carries the hop.** Past the authority's edge every hop inside a cell
  is plaintext under istio ambient's ztunnel mTLS, the workload's identity is
  its ServiceAccount's SPIFFE ID — the mesh principal a presence document
  names, not an SVID this process presents — and TLS ends at the edge. So this
  listener presents no certificate and verifies no caller. The previous generation
  served TLS 1.3 under a projected X.509-SVID, verified callers against a
  projected anchor, admitted them by three provisioned peer files, re-verified
  every established connection once a second in both directions and refused
  session resumption; `identity.go` and all of it are **deleted, not fenced**,
  because every one of those checks was this process re-deciding what the
  cell decides for every workload. If you are about to add a check on who is
  on the other end of a connection, you are rebuilding what this cutover
  removed; what this process still decides is what a caller may do once
  admitted (the authority's Check of the request's Work Context) and where the
  viewer's Work Context may travel (below).
- **A plaintext destination is admitted only where the mesh is, by the SDK's
  rule and never by a copy of it.** Each relayed module's hop address goes
  through `workcontext.AdmitEndpoint` when its relay is opened: `https` to any
  host; `http` to a loopback host on a local run, or to an in-cluster Service
  address (`<svc>.<ns>.svc[.<domain>]`) when the composition asserts
  `internal-transport/mesh-protected=true`; anything else refuses the boot.
  The assertion is read ONCE, in `loadConfig`, into `meshTransport`, and
  answered from that snapshot wherever the rule asks. The snapshot keeps the
  SDK's three answers three (unset, set to a value, unreadable) and never trims
  the value: only the literal `true` asserts. Do not add a boolean beside it.
- **Every Work Context is issued by the authority, and none is minted here.**
  A handler's gateway acts for whom the authority's `Check` says the request's
  context is for, naming the route so the solution's delivered policy applies;
  `ForParent` asks for a child of it through one of the solution's bindings,
  `ForBinding` for the solution's own through a binding. An issued context is
  cached for the request under the ask, single-flight, with the scopes
  deep-copied at the ask, and renewed before its expiry; a 401/403 refusal is
  held for the request rather than re-asked.
- **Nothing is reported to the host, and the frontend is declared in one
  file.** The CLI reads `solution.frontend.codefly.yaml` beside the backend's
  `service.codefly.yaml`, the same file this runtime embeds
  (`Manifest.Frontend`, `go:embed`) and serves its manifest from
  (`frontend.go`): two readers of one file cannot disagree, where a Go field
  beside a file could. Do not add a Go field for anything the host lists a
  solution under, and do not report anything about this process to the host:
  a process cannot declare what the composition did not.
- **Fail closed, with no exception for a counterpart's current state.** A
  request whose Work Context the authority does not check is refused before a
  handler or a tool runs; a module address outside the SDK's admitted
  transport rule is refused at boot. A statement about someone else's
  deployment is not a reason to leave a hole open for as long as the
  counterpart takes.
- The published contract, when a solution declares one, is **declared, not
  derived**. A scope ceiling computed
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
- **The MCP surface verifies no token, and must not start.** It is the
  transport only — the SDK's stateless Streamable HTTP handler at
  `/v1/<id>/mcp` and the middleware that binds each call to its viewer — and a
  call is admitted exactly as a handler route is, by the authority's `Check`
  naming the route. A tool's arguments are written by a model: no identity
  ever comes from them. How an agent client obtains a Work Context for a
  solution is the authority's to answer, not a second admission rule here.
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
   carries no address literal at all.
   If you are typing an address, a port or a credential, you are encoding
   something true only on your machine for the next ten minutes; if you are
   deriving one the owner has not published, you are encoding a guess about
   somebody else's deployment.
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
   this suite makes that easy to get wrong: it is hermetic. The authority and
   every relayed module are stand-in servers on `127.0.0.1`, so a green run
   proves the wire shapes and refusals this package produces — never that a
   real authority issues a Work Context or that a composed module accepts one. If you did not run it against a real
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

- The suite takes about a minute under `-race` and is hermetic: the authority
  is a gRPC stand-in on `127.0.0.1` answering `Check` and `Issue`, each relayed
  module a gRPC stand-in behind it, and the projected workload credential a
  file the test writes into a temp directory.
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
  full configuration and env-override table, the authority interface, plain
  HTTP inside the cell, the declared frontend file, the published contract,
  the passthrough and the MCP surface. It also carries the migration note: the
  saas-host mode is deleted, and nothing bridges the two.
- The package doc comment and the comments in [`solution.go`](solution.go),
  [`authority.go`](authority.go), [`passthrough.go`](passthrough.go),
  [`frontend.go`](frontend.go), [`contract.go`](contract.go) and [`mcp.go`](mcp.go) — why a refusal, a renewal point or a cache
  lifetime is what it is. Several record a failure mode that is not obvious from
  the code; read the one next to what you are changing before you change it.
- `.claude/skills/` — procedures an agent repeats, loaded only when relevant.
  None exist yet, because nothing here repeats beyond the four commands above.
  Add one instead of growing this file.

The optional frontend declaration uses Core's `solutionhost.ParseFrontend` and
its types directly. Nil is headless; a present malformed file refuses boot.
Do not introduce a second parser, size limits or a fixed client-kind inventory.
