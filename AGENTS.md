# Working in solution-runtime-go

This repository owns the generic Go runtime for **codefly solutions** — modules
deployed independently of the host they extend, with no build-time coupling. It
owns what every solution needs identically: configuration resolution through the
codefly SDK, self-registration with the host frontend and the gateway (the
credential exchanges and their heartbeats), CORS, Module Federation asset
serving, the capability handshake, the manifest, and the gateway client a
handler uses to read composed modules on the viewer's behalf.

It owns none of the counterparts it talks to. The registration surfaces and
their admission rules belong to the host (`codefly-dev/module-saas-starter`) and
the gateway; endpoint, port and secret resolution to `codefly-dev/sdk-go`;
workspace and manifest types to `codefly-dev/core`; running a composition and
provisioning its secrets to `codefly-dev/cli`. Everything here is a library —
one Go package at the repository root, consumed by solution repos as
`github.com/codefly-dev/solution-runtime-go` at a `vX.Y.Z` tag.

## Boundaries

- Read [README.md](README.md) first. It is the contract this runtime offers its
  consumers and it is kept current with the code, down to the env-override
  table. A behaviour change the README describes is unfinished until the README
  describes the new one.
- The exported surface (`New`, `Handle`, `HandleRequest`, `Serve`, `Unary`,
  `Gateway`, `Scope`, `ClientError`, `GatewayError`) is pinned at a tag by repos
  you cannot see from here. A change that breaks a consumer carries a `!` in the
  commit type and says so in the PR body.
- Configuration is resolved in one place, `loadConfig`, and checked in one
  place, `validate()`. New configuration follows both: resolved through the SDK,
  with an explicit env override, refused loudly at boot when unresolved. Do not
  read the environment from the interior.
- Validate at the boundary — boot, and the headers a request arrives with — not
  between internal callers. `validate()` is the model: each refusal names the
  variable or the provisioning path that fixes it.
- A registration that cannot attest which publisher it speaks for is not a
  registration. There is no fallback to the shared cluster-internal token and no
  downgrade path when an exchange answers `404`.
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
   it is the public URL built from the *resolved* port. Both token-exchange URLs
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
test -z "$(gofmt -l ./*.go)"
```

Go comes from `go.mod` (1.27). Nothing else is needed: no Docker, no
credentials, no running composition.

- The suite takes ~20s, most of it two heartbeat tests that wait on real wall
  time (10s and 5s). That is not a hang — hence the 5m timeout.
- The formatting gate globs `./*.go`, so it covers the root package and only
  the root package. A package added in a subdirectory is vetted and tested by
  the commands above but not format-checked; widen the glob in the same PR.
- Dependency pins are how fixes from `core` and `sdk-go` reach consumers:
  `go get github.com/codefly-dev/core@vX.Y.Z && go mod tidy`, then the four
  commands above. `go mod tidy` is a no-op on a clean tree, so a diff it
  produces is part of your change. Say in the commit *why* the pin moves and
  reference the owning issue — "bump" is not a reason.
- Releases are plain `vX.Y.Z` tags on `main`; there is no release workflow. The
  tag is what consumers pin, so it is cut from a commit whose gate is green.

## Where the depth is

Keep this file short; add depth to the file that owns the subject.

- [README.md](README.md) — the consumer-facing contract: handler errors, the
  full configuration and env-override table, self-registration and its
  provisioning, consumed-module federation, and reading a
  Work-Context-authenticated module.
- The package doc comment and the comments in [`solution.go`](solution.go) —
  why a refusal, a backoff cap or a cache lifetime is what it is. Several
  record a failure mode that is not obvious from the code; read the one next to
  what you are changing before you change it.
- `.claude/skills/` — procedures an agent repeats, loaded only when relevant.
  None exist yet, because nothing here repeats beyond the four commands above.
  Add one instead of growing this file.
