# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns registration
(host + gateway, with heartbeat), CORS, Module Federation asset serving, the
capability handshake, the manifest, serving the solution's MCP server to agent
clients, and the gateway client each handler uses to read composed modules on
the viewer's behalf.

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
| Host issuer (MCP) | the resolved host frontend origin — the host is the authorization server an MCP client authenticates against (see [Exposing an MCP server](#exposing-an-mcp-server)); checked at boot only when `ServeMCP` is declared | `HOST_ISSUER_URL` |
| Public MCP URL | none — the resource identifier is then reconstructed per request from `x-forwarded-proto` / `x-forwarded-host` / `x-forwarded-prefix` | `MCP_PUBLIC_URL` (must end in `/mcp`) |

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
issuer's reason (which names the missing permission), and is still served
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
verbatim under the code its HTTP status maps to, and anything else is reported
by kind only. `PassthroughOperations` renders the declaration for the interface
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

`Serve` resolves the gateway and api.consumes from the composition and
registers with the host, so a solution cannot run its own passthrough in a
test through it. Package
`github.com/codefly-dev/solution-runtime-go/passthroughtest` serves the real
passthrough — `Server.PassthroughHandler`, the handler `Serve` mounts, behind
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
| `Host.RefuseMints(func(Mint) *Refusal)` | Decides each mint: a non-nil `Refusal` refuses it as accounts would (default status 403), so the page sees `permission_denied` with its message. |
| `Host.Mints()`, `Host.Calls()` | Every mint asked for (audience, scopes, org, session, bearer, the token answered), and every call forwarded to a module, each with the `Mint` whose capability it presented — how a test asserts the authority each method was called under. |
| `Start(t, host, consumes...)` / `Handler(host, consumes...)` | The passthrough served for the declaration, or the bare handler and the error `Serve` would refuse the declaration with. |
| `Solution.Client()`, `ClientAs(Viewer)`, `BaseURL(as)` | A client that calls as `DefaultViewer` (or the viewer given), setting the bearer and the `x-org-id` / `x-session-id` headers the gateway stamps; and the base URL a module's generated client takes. |

What a green test there proves is the solution's side: the declaration, the
authority each method mints, the fields that reach the page, stream bounds and
cancellation. It never proves that a real host admits the solution, that
accounts grants the scopes, or that the real module answers its binding the way
the test's stand-in does.

### Exposing an MCP server

A solution exposes its experience to an agent client — Claude Code, Claude
Desktop, any MCP client — the way it exposes it to a browser: as the signed-in
person, through the host's gateway, with the same authority. The solution owns
its tool surface; this runtime owns serving it. These are the three lines:

```go
solution.New(solution.Manifest{ID: "wiki", Title: "Wiki"}).
    ServeMCP("wiki", "v1.0.0", func(srv *mcp.Server) {
        mcp.AddTool(srv, &mcp.Tool{Name: "ask_wiki", Description: "ask the wiki a question"}, askWiki)
    }).
    Serve()
```

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
    robin, err := gw.ForModule(ctx, "robin", solution.Scope{ResourceKind: "conversations", Actions: []string{"create"}})
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
| No `authorization` | `401` with `WWW-Authenticate: Bearer resource_metadata="…"`. An MCP client's first contact is unauthenticated, and this challenge is what tells it where to find the authorization server. |
| A bearer, but none of `x-user-id`, `x-org-id`, `x-session-id` stamped | `401` with the same challenge: nothing but the gateway may reach this endpoint, so either the request did not come through it or it did not authenticate the bearer — and a client that dialled the wrong address can still discover the right issuer from the challenge. |
| `x-session-id` stamped empty | `403`, naming the `x-credential-kind` the gateway stamped. An organization API key authenticates a principal and no session, and every tool call that acts for the viewer mints a Work Context rooted in one, so this is refused at the boundary rather than once per tool call — where the same refusal would read as the tool being broken. Another token cannot fix it, so it carries no challenge. |

#### The resource identifier and the issuer

The `resource` in the metadata document is what a client asks the authorization
server for a token for (RFC 8707) and what its token is audience-bound to, so it
must be the **public** MCP URL — not this process's listen address, not the
in-cluster address the gateway dials. The runtime cannot resolve it: the origin
is the host's, and the path is the host's route layout, which this runtime
deliberately does not encode (see
[Where the host reaches the solution](#where-the-host-reaches-the-solution)).

So `MCP_PUBLIC_URL` is it when set, and must end in `/mcp` — the metadata
document's own URL is derived from it by swapping that suffix, the same pairing
the registration token URLs use, refused at boot for the same reason when it
cannot be made. Unset, the identifier is reconstructed per request from
`x-forwarded-proto`, `x-forwarded-host` and `x-forwarded-prefix`, and `ServeMCP`
logs at boot that it is doing so: a proxy that forwards no prefix yields an
identifier missing the path it stripped, which a conforming client rejects and a
tolerant one binds to the wrong resource. Set it in any deployment.

`authorization_servers` is the host issuer resolved at boot — by role, like every
other host endpoint — and is never derived from a request, so a crafted `Host`
header cannot point a client at an authorization server of someone's choosing.
The resolved value is the address this composition reaches the host at: right for
a local run, and in a deployment an in-cluster address no public client could
reach, which is what `HOST_ISSUER_URL` is for. A solution that declares
`ServeMCP` and resolves no issuer is refused at boot; one that declares no MCP
server is unaffected.

Two things about discovery belong to the host, not to this runtime. It must admit
an unauthenticated `GET` on
`/solutions/<id>/.well-known/oauth-protected-resource`, or no client can read the
document the challenge points at. And that is where the document is — on the
solution's own path — whereas RFC 9728 §3.1 also defines a location derived from
the resource's path, `/.well-known/oauth-protected-resource/solutions/<id>/mcp`,
at the **host's** root. A client that follows the `resource_metadata` of the 401,
as an MCP client does, reaches the document either way; one that only guesses the
derived location needs the host to serve it there.

#### Connecting

Until the host is an MCP-conformant OAuth 2.1 authorization server, a client
presents a token it already has, which the gateway already accepts:

```sh
claude mcp add --transport http wiki https://<host>/solutions/<id>/mcp \
    --header "Authorization: Bearer <access token>"
```

Once the host supports it, the 401 challenge and the metadata document above are
the whole of what a client needs to authenticate on its own.

#### Testing the tools: `MCPHandler`

`Serve` resolves the gateway and the issuer from the composition and registers
with the host, so a solution cannot drive its own tools in a test through it.
`Server.MCPHandler` serves the MCP surface exactly as `Serve` serves it — the
same endpoint, the same metadata document, the same refusals, mounted by the same
code — against an environment the test supplies. Nothing else of the solution is
served and nothing registers anywhere:

```go
handler, err := s.MCPHandler(solution.MCPEnvironment{
    GatewayURL: fakeHost.URL, // answers the accounts StartTask mint and /v1/<as>/*
    IssuerURL:  "https://host.test",
})
server := httptest.NewServer(handler)
session, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "v0"}, nil).
    Connect(ctx, &mcp.StreamableClientTransport{
        Endpoint:   server.URL + solution.MCPPath,
        HTTPClient: &http.Client{Transport: stampsTheViewersIdentity{}},
    }, nil)
```

What a green test there proves is the solution's side: the tools it offers, the
authority each one mints, and the refusals its callers get. It never proves that
a real gateway stamps what the test's `RoundTripper` stamps, that accounts mints
a Work Context, or that a real MCP client's OAuth flow completes against the
host.

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

> **Note:** SDK in-process endpoint resolution for a solution composed on an
> out-of-repo host depends on codefly-core accepting the composed module path in
> its workspace loader (codefly-dev/core#365, merged); the `core`/`sdk-go` pins
> in `go.mod` carry that fix, so no `replace` is needed.
