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

## Handler errors

Return `ClientError` for an explicitly public validation message. Connect errors
returned by `Unary` retain actionable statuses: authentication 401, permission
403, missing resource 404, invalid input 400, conflict 409, precondition 412,
quota 429, unavailable 503 and deadline 504. Other RPC failures return 502.
Only generic status text reaches the browser; wrapped/upstream details remain
available to the handler. No request is retried or replayed.

REST adapters can return `&solution.GatewayError{StatusCode: resp.StatusCode}`
after a non-success response through the gateway. The runtime preserves 4xx,
503 and 504; unexpected statuses and other server failures become 502. This
error carries no raw body, URL or headers. Work Context mint refusals use this
same path. Untyped errors retain the existing 502/public-error-string behavior,
so handlers must not put private details in them. Consumers using an older runtime
or flattening failures into strings must adopt these typed errors to benefit.

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
| Public URL | none — the manifest is then registered as the root-relative path `/assets/mf-manifest.json` on this backend (see [Where the host reaches the solution](#where-the-host-reaches-the-solution)) | `PUBLIC_URL` |
| Gateway URL (auth-gateway `rest`) | resolved by role — the single module owning the `auth-gateway` `rest`/`rest` endpoint, discovered from the injected carriers (or the workspace, run locally) | `GATEWAY_URL` |
| Host frontend URL | resolved by role — the single module owning the `frontend` `http`/`http` endpoint, discovered the same way | — (feeds the host register URL) |
| Host register URL | `<frontend>/api/solutions/register` | `HOST_REGISTER_URL` |
| Gateway register URL | `<gateway>/solutions/_register` | `GATEWAY_REGISTER_URL` (must end in `/solutions/_register`, see below) |
| Gateway module register URL | `<gateway>/modules/_register` | `GATEWAY_MODULE_REGISTER_URL` |
| Gateway module token URL | the module register URL above with `/modules/_register` swapped for `/modules/_registration-token`, so it keeps that gateway's base path | `GATEWAY_MODULE_REGISTRATION_TOKEN_URL` |
| Gateway solution token URL | the gateway register URL above with `/solutions/_register` swapped for `/solutions/_registration-token`, same reasoning | `GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL` |
| Internal-auth token | `codefly.For(ctx).WorkspaceSecret("internal-auth", "CODEFLY_INTERNAL_TOKEN")` — the namespaced secret Codefly injects | `CODEFLY_INTERNAL_TOKEN` |
| Solution registration secret | `codefly.For(ctx).WorkspaceSecret("solution-registration", "SECRET")` — see [Self-registration](#self-registration) | `CODEFLY__SOLUTION_REGISTRATION_SECRET` |
| Registration beat interval | `15s` | `CODEFLY__SOLUTION_REGISTRATION_INTERVAL` |
| Self upstream | the reachable self endpoint Codefly injects as `CODEFLY__SELF_ENDPOINT__<MODULE>__<SERVICE>__HTTP__HTTP` (core ≥ v0.5.6); without it, the listen address `http://localhost:<port>` | `SELF_UPSTREAM` |
| Deployed or local | `CODEFLY__RUNTIME_CONTEXT`, injected by Codefly: `native`/`nix`/`container`/`free` (or unset) is a local run, anything else (a GitOps render's `kubernetes`, core ≥ v0.5.6) a deployment | — |
| MF assets | `Manifest.Assets` when set (see below), else the `../fe-remote/dist` directory | `ASSETS_DIR` (directory only) |

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

### Where the host reaches the solution

The two registrations carry two different addresses, for two different
callers, and neither is this process's listen address:

- **`manifestUrl`** (host registration) is loaded by the **viewer's browser**.
  With no `PUBLIC_URL` it is the root-relative path `/assets/mf-manifest.json`
  on this backend, and the host resolves it against the route by which it
  reaches the solution — the runtime does not know, and does not encode, the
  host's route layout. `PUBLIC_URL` makes it absolute on that origin instead,
  for an operator who exposes the solution's assets directly.
- **`upstream`** (gateway registration) is dialled by the **gateway**. It is
  the address Codefly injects for reaching this service
  (`CODEFLY__SELF_ENDPOINT__…`, beside the `CODEFLY__ENDPOINT__…` carrier that
  stays the listen address), and `SELF_UPSTREAM` overrides it. `PUBLIC_URL` no
  longer feeds it: the browser's origin is not the gateway's route.

In a **deployed** runtime context (`CODEFLY__RUNTIME_CONTEXT` outside the local
kinds above) `validate()` refuses to boot when either address is loopback
(`localhost`, `*.localhost`, `127.0.0.0/8`, `::1`, the unspecified address): a
deployed solution that registered its listen address booted, looked healthy, and
was proxied by the gateway to the gateway itself, while the product reported it
as failed to load. The environment's *name* is never consulted — an environment
called `local-dogfood` may well be deployed.

Until core v0.5.6 is released, the self endpoint is read from that carrier by
name in one helper (`selfEndpoint`), and a cell rendered by an older core has
neither the carrier nor the runtime-context signal: it falls back to the listen
address and is not refused. Both switch to the core/SDK accessors when released.

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

There is no other credential, so there is no fallback. A boot without a
provisioned secret is refused by `validate()`, naming the two provisioning
paths, rather than coming up looking healthy while the host serves nothing.
A `404` on `/solutions/_registration-token` fails the beat and names the route:
either the host does not serve publisher-bound registration (module-saas-starter
< v0.0.61, which this runtime does not support) or the exchange URL is wrong
(`GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL`, or the `GATEWAY_REGISTER_URL` it is
derived from). The shared cluster-internal token is never presented on a
registration: it proves no publisher, and a downgrade path would let anything
able to answer `404` at that URL turn the publisher-bound credential back into
it.

Only a `401`/`403` from the exchange is reported as a credential fault (no
`SOLUTION_REGISTRATION_SECRETS` entry for this id, or a secret that does not
match its digest) — those are the statuses accounts answers after judging the
secret. A `5xx` is reported as `host unavailable (status N), retrying` with the
gateway's own error body, and any other status as a failure with its body; none
of them names the provisioning, and the heartbeat keeps retrying all of them.

A refusal that carries reasons (the host's `409 incompatible_runtime`, say) is
logged with them, again whenever the reasons change and not only when the status
does — up to a handful of distinct reasons per status, after which the log says
it is suppressing them. The reasons are text the host chooses, so one that
varies per attempt (the `jti` of the token it just burned, say) must not be able
to turn the log into a stream of one line per beat.

Two consequences of deriving the exchange from the registration endpoint are
worth stating outright, because both turn a working deployment into a failing
one:

- `GATEWAY_REGISTER_URL`, if you override it, **must end in
  `/solutions/_register`** — that suffix is what the exchange URL is derived
  from by swapping it. An override with any other path cannot be paired, and
  the boot is refused naming both this variable and
  `GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL`, which you can set explicitly
  instead. This variable was free-form before the exchange existed.
- Both self-registrations now mint through the gateway, so a gateway outage
  fails the **host frontend** registration too, even though the frontend is
  healthy. A beat that never reached its registration surface minted nothing,
  so it retries on a much shorter backoff cap (30s) than a beat the surface
  actually refused (2m) — the long cap exists to bound audited mints, and an
  unreachable dependency produces none, so paying it there would only keep this
  solution out of a healthy host's nav for longer than necessary.

Every registration request refuses to follow redirects, for the same reason none
of them may be proxied: `net/http` strips only `Authorization`, `WWW-Authenticate`
and `Cookie` when a redirect crosses hosts, so the `X-Codefly-*` headers these
requests carry — the plaintext registration secret and the cluster-internal
token — would be handed to whatever a `Location` named.

A beat is not free any more: each self-registration beat runs an exchange whose
every success is an audited mint on the issuer, so at the 15s default across two
surfaces a solution mints roughly 11.5k tokens a day. The right period is
whatever the host's registration TTL allows, which this runtime cannot observe —
set `CODEFLY__SOLUTION_REGISTRATION_INTERVAL` (a Go duration, minimum `1s`) when
you know both numbers. An unparseable or too-small value fails the boot rather
than falling back to the default, so a typo cannot silently restore the fast
beat you were trying to slow down.

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

The Task is rooted in the viewer's **session**, which arrives the same way:
`x-session-id`, stamped from the same verified claims and replacing anything the
caller sent. That session is the one accounts sealed the selected organization
into, so the Task it roots is attributable — the mint accounts journals names the
session that asked for it. A session id the runtime invented would be a
well-formed UUID naming no session, attributable to nothing.

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

This traffic is not proxied, for the same reason registration traffic is not:
every gateway target is composition-local, and these requests carry the viewer's
bearer and the capability minted for them in headers.

> **Note:** SDK in-process endpoint resolution for a solution composed on an
> out-of-repo host depends on codefly-core accepting the composed module path in
> its workspace loader (codefly-dev/core#365, merged); the `core`/`sdk-go` pins
> in `go.mod` carry that fix, so no `replace` is needed.
