# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns registration
(host + gateway, with heartbeat), CORS, Module Federation asset serving, the
capability handshake, the manifest, and the gateway client each handler uses
to read composed modules on the viewer's behalf.

A solution author writes a manifest and one handler:

```go
solution.New(solution.Manifest{ID: "my-solution", Title: "My Solution"}).
    Handle("/thing", func(ctx context.Context, gw *solution.Gateway) (any, error) {
        resp, err := solution.Unary[Req, Resp](ctx, gw, "/pkg.Service/Method", &Req{})
        return resp, err
    }).
    Serve()
```

The gateway URL, the caller's bearer, and the wire protocol are hidden.

## Configuration

The runtime hardcodes nothing. On boot `Serve` calls
`codefly.LoadEnvironmentVariables()` to load Codefly's injected carriers, then
`loadConfig` resolves every address, port, and secret through the codefly Go SDK
(`github.com/codefly-dev/sdk-go`), falling back to the local native workspace
map when not running under the runtime. Each value has an explicit env override;
the SDK-resolved value is the default.

| What | SDK resolution | Env override (default) |
|---|---|---|
| Own listen port | `codefly.For(ctx).Endpoint("http").NetworkInstance()` — the Codefly-assigned port, not a fixed default | `PORT` |
| Public URL | `http://localhost:<port>` | `PUBLIC_URL` |
| Gateway URL (auth-gateway `rest`) | resolved by role — the single module owning the `auth-gateway` `rest`/`rest` endpoint, discovered from the injected carriers (or the workspace, run locally) | `GATEWAY_URL` |
| Host frontend URL | resolved by role — the single module owning the `frontend` `http`/`http` endpoint, discovered the same way | — (feeds the host register URL) |
| Host register URL | `<frontend>/api/solutions/register` | `HOST_REGISTER_URL` |
| Gateway register URL | `<gateway>/solutions/_register` | `GATEWAY_REGISTER_URL` |
| Gateway module register URL | `<gateway>/modules/_register` | `GATEWAY_MODULE_REGISTER_URL` |
| Gateway module token URL | the module register URL above with `/modules/_register` swapped for `/modules/_registration-token`, so it keeps that gateway's base path | `GATEWAY_MODULE_REGISTRATION_TOKEN_URL` |
| Gateway solution token URL | the gateway register URL above with `/solutions/_register` swapped for `/solutions/_registration-token`, same reasoning | `GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL` |
| Internal-auth token | `codefly.For(ctx).WorkspaceSecret("internal-auth", "CODEFLY_INTERNAL_TOKEN")` — the namespaced secret Codefly injects | `CODEFLY_INTERNAL_TOKEN` |
| Solution registration secret | `codefly.For(ctx).WorkspaceSecret("solution-registration", "SECRET")` — see [Self-registration](#self-registration) | `CODEFLY__SOLUTION_REGISTRATION_SECRET` |
| Self upstream | `<public-url>` | `SELF_UPSTREAM` |
| MF assets dir | `../fe-remote/dist` | `ASSETS_DIR` |

The host it plugs into is named by Codefly-convention **service roles**, not by
its workspace module name: the runtime discovers the single module that owns each
role — from the injected endpoint carriers when deployed, or the workspace on
disk when run locally — so a solution composing the host as `saas`,
`saas-starter`, or any other name resolves identically (codefly-dev/core#382).
The roles are overridable: `CODEFLY_HOST_FRONTEND` (default `frontend`),
`CODEFLY_HOST_GATEWAY` (default `auth-gateway`, falling back to the pre-v0.0.49
`auth-sidecar` when unresolved). `CODEFLY_HOST_MODULE` is empty by default and
only needs setting to disambiguate a composition where **more than one** module
exposes the same role — otherwise an ambiguous match resolves to nothing and the
runtime fails loud at boot rather than picking a host arbitrarily. Concrete
addresses always come from the SDK.

### Self-registration

On boot the runtime self-registers on a 15s heartbeat with **both** the host
frontend (host registration: the manifest) and the gateway (gateway
registration: the upstream).

A host on module-saas-starter ≥ v0.0.61 binds each registration to the
solution's **publisher** (`module/SOLUTION_REGISTRATION.md` there): both
surfaces admit a registration only against a short-lived, solution-bound token
that accounts mints to a caller presenting the registration secret the
composition declared for that id, and neither accepts the shared
cluster-internal token any more — it attests to no publisher. The runtime
obtains that token by presenting its **solution registration secret** (plus the
internal token, the gateway's perimeter check) to
`/solutions/_registration-token`, and presents it as
`X-Codefly-Solution-Registration` on both registrations. Each surface burns a
token on use, so — unlike the module credential below — nothing is cached: a
fresh token is minted for every beat, on each surface.

Provisioning both halves is the composition's job, and works the same for a
local `codefly run solution` and a deployed cell:

- **host side** — declare `<solution-id>:sha256hex` in the saas `federation`
  group's `SOLUTION_REGISTRATION_SECRETS` (separately from
  `MODULE_REGISTRATION_SECRETS`: a solution credential additionally publishes
  host-origin code, so the two are never shared);
- **solution side** — provision the plaintext as the `SECRET` key of the
  `solution-registration` workspace secret group
  (`codefly config generate solution-registration SECRET` locally; the cell's
  secret store when deployed) and declare that group as a
  `workspace-configuration-dependencies` entry of the solution's backend, so
  the SDK injects it. `CODEFLY__SOLUTION_REGISTRATION_SECRET` is an explicit
  override.

One composition boots against either host version. With no secret provisioned
the runtime registers the way it did before v0.0.61's contract — presenting the
cluster-internal token — and the boot log says which half is missing, so
against a newer host "rejected (status 401)" is not read as a gateway fault.
With a secret provisioned but a host that offers no exchange (`404` on
`/solutions/_registration-token`: a host before v0.0.61), the beat presents the
cluster-internal token instead, says so once, and keeps trying the exchange on
every beat so a host upgrade is picked up without a restart. A refusal that
carries reasons (the host's `409 incompatible_runtime`, say) is logged with
them.

The manifest declares the contract majors it is built against
(`schemaVersion: 1`, `frontend.hostContract: 1`) rather than leaving the host
to assume them; a host checks both before activating a remote.

### Consumed-module federation

A solution that declares `api.consumes` also registers each consumed module's
upstream with the gateway, so `/v1/<as>/*` proxies to it. Codefly projects the
targets into `CODEFLY__API_CONSUMES`; each gets its own 15s registration
heartbeat alongside the two above.

The gateway does **not** accept the shared internal token on `/modules/_register`
— it admits a registration only against a short-lived token signed by accounts
and bound to a single prefix, so holding the credential for one module never lets
you claim another's route. The runtime obtains that token per consumed module by
presenting the module's own **registration secret** to
`/modules/_registration-token`, which the gateway brokers to accounts (a composed
module cannot reach accounts' internal listener itself). The token is reused
until shortly before it expires — or until half its life is gone, if the issuer
chose a lifetime shorter than that lead, since how long a credential lives is
the issuer's call and not this runtime's to veto.

Obtaining one is an audited security event on accounts, so the runtime does not
answer every failure by obtaining another. A refusal buys exactly one fresh
token: the gateway refusing a token minted moments earlier is not refusing it for
being stale, and re-minting cannot fix whatever it is refusing it for. Beats that
fail also back off, doubling up to two minutes, so a broken gateway costs a
bounded number of exchanges however long it stays broken — and the runtime keeps
retrying, at a rate that will not flood the issuer's audit log, until it
recovers. A response carrying no usable expiry is refused rather than cached, and
its two causes — an issuer that sent no `expiresAt` at all, and a clock skewed
past the credential's lifetime — are reported separately, because they have
different fixes.

No registration request is unbounded: a gateway that accepts one and never
answers surfaces as a failed beat rather than silently parking that heartbeat
for the life of the process.

Registration traffic — the exchange and all three heartbeats — never goes
through an HTTP proxy: every target is composition-local, and these requests
carry the registration secret, the internal token, and the signed token in
headers.

Those secrets arrive in `CODEFLY__MODULE_REGISTRATION_SECRETS` as
comma-separated `prefix:secret` entries — the plaintext twin of the
`prefix:sha256hex` digests the same composition declares to accounts
(`MODULE_REGISTRATION_SECRETS`). A consumed module with no secret cannot be
registered, so the runtime skips it with a log naming this variable rather than
beating against a guaranteed 401. Provisioning both halves is the composition's
job (`codefly run solution`).

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
seen. It names no actor principal, which makes the viewer both owner and actor
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

Minting is an audited event on accounts, so capabilities are cached per (org,
audience, scopes) and shared by every gateway derived from the one a handler was
given: a handler reading a module repeatedly mints once, and so does one that
fans the same ask out across goroutines — concurrent asks wait on the single
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

This traffic is not proxied, for the same reason registration traffic is not:
every gateway target is composition-local, and these requests carry the viewer's
bearer and the capability minted for them in headers.

> **Note:** SDK in-process endpoint resolution for a solution composed on an
> out-of-repo host depends on codefly-core accepting the composed module path in
> its workspace loader (codefly-dev/core#365, merged); the `core`/`sdk-go` pins
> in `go.mod` carry that fix, so no `replace` is needed.
