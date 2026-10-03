# Working in solution-runtime-go

This repository owns the generic Go runtime for **codefly solutions** — modules
deployed independently of the host they extend, with no build-time coupling. It
owns what every solution needs identically: configuration resolution through the
codefly SDK, obtaining this execution's credential once from the projected
service-account token, a listener that presents the workload's own X.509-SVID,
CORS, Module Federation asset serving, the capability handshake, the manifest,
the published authority contract, and the gateway client a handler uses to read
composed modules on the viewer's behalf.

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
on `Server.PassthroughHandler`, the handler `Serve` mounts.

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
  suite until this file describes the exception.
- **Never sign, parse or verify a Work Context here.** There is one
  implementation, Core's; this runtime obtains a credential through the SDK's
  mint client, carries it as the string it travels as, and lets the far end
  decide. It declares none of a capability's fields and holds no verifier —
  core's needs the issuer's live revision, replay, grant and seal sources, which
  a solution does not have. `work_context_boundary_test.go` fails on a signing
  primitive, on a `WorkContext`-named declaration of this package's own, and on
  a call to a verifier. This is not a style rule: a second signed encoding grew
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
- Validate at the boundary — boot, and the headers a request arrives with — not
  between internal callers. `validate()` is the model: each refusal names the
  variable or the provisioning path that fixes it.
- The listener presents this workload's own identity and there is no plain-HTTP
  listener. A configuration that cannot produce one is refused at boot naming the
  material, because a solution serving plain HTTP is refused at the edge instead,
  for a reason only the edge can see. Where the identity comes from is the
  platform's: `IdentitySource` is the hook, and the default reads the pair the
  platform projects through the SDK's reloader.
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
- **Peer trust is re-read per connection in BOTH directions.** Inbound, per
  handshake through `GetConfigForClient`; outbound, per dial through
  `DialTLSContext` with idle reuse capped, because a pooled connection that
  never re-dials makes per-dial reloading meaningless. The outbound half went
  unanswered through two review rounds while the inbound argument — judging by
  a stale anchor admits whoever should be refused — was already written down
  here. It applies harder outbound: those destinations receive the projected
  token, the viewer's bearer and this workload's credential.
- **Authentication is not authorisation.** Every workload in the trust domain
  holds a certificate from the same anchor, the consumed modules included, so
  the admitted caller set is provisioned
  (`workload-identity`/`ALLOWED_CALLERS`) and refused at boot when absent. A
  listener that verifies every caller and admits all of them lets a consumed
  module set its own `x-org-id`/`x-session-id` and drive mints under this
  workload's attestation.
- **A terminal credential refusal ends the process; a transient one does not.**
  `ErrMintRefused` and `ErrRevoked` at renewal fail `/health` and end `serve`
  with the reason. `ErrMintUnavailable` must not: it is transient by
  construction and exiting on it is a crash loop. The boot and the run have to
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
- Tests live beside the code in the same package. Every behaviour change brings
  one, and the counterpart it exercises is an `httptest` server, never a real
  host.

## How to behave when something does not work

Fleet standard, governed by the handbook's agent-context track
([obin-ai/handbook#68](https://github.com/obin-ai/handbook/issues/68)). These
are not style preferences; each is a rule an agent broke at real cost, and this
repository is the runtime that cost was measured against.

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
4. **Never hardcode what the system resolves.** This package resolves every
   address, port and secret through the SDK; the single `localhost` literal in
   it is the self upstream's listen-address fallback, built from the *resolved*
   port and refused by `validate()` in a deployed runtime context. Both token-exchange URLs
   are derived from their register URLs by swapping the path suffix, which is
   why an override that drops the documented suffix cannot be paired and is
   refused at boot rather than guessed at. If you are typing an address, a port
   or a credential, you are encoding something true only on your machine for the
   next ten minutes.
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

- The suite is fast (a few seconds) and hermetic: the host's mint, its gateway
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
  [`contract.go`](contract.go) — why a refusal, a renewal point or a cache
  lifetime is what it is. Several record a failure mode that is not obvious from
  the code; read the one next to what you are changing before you change it.
- `.claude/skills/` — procedures an agent repeats, loaded only when relevant.
  None exist yet, because nothing here repeats beyond the four commands above.
  Add one instead of growing this file.
