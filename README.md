# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns configuration
resolution, this execution's one credential, a listener that presents the
workload's own identity, CORS, Module Federation asset serving, the capability
handshake, the manifest, the published authority contract, and the gateway
client each handler uses to read composed modules on the viewer's behalf.

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
  mint endpoint: the boot fails, naming the endpoint it could not reach, and
  the process exits non-zero.

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
same way, by a signed document bound to one approved build. This runtime's only
outbound act at boot is to obtain its own credential once, from the
service-account token the platform projects for it; it renews that credential
when it expires and otherwise says nothing to anyone. Health is **answered**,
never pushed: the host probes the destination its own presence document names,
and nothing this process answers can make it present.

Four things follow, and each is a boot failure rather than a degraded run:

| | |
|---|---|
| The listener presents this workload's X.509-SVID over TLS | there is no plain-HTTP listener, because the host refuses a plain-HTTP destination |
| The credential is obtained once, before the listener exists | a refusal is terminal and never retried; an unavailable mint is waited out inside a bounded deadline — see [One credential per execution](#one-credential-per-execution) |
| The authority-bearing values are read once and frozen | the credential is sealed to the values it was minted under, so a value that drifts is an error, never a reload |
| The contract is published, and the declaration is held to it | an ask outside its declared ceiling fails the boot — see [The published contract](#the-published-contract) |

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
`loadConfig` resolves every address, port, and path through the codefly Go SDK
(`github.com/codefly-dev/sdk-go`), falling back to the local native workspace
map when not running under the runtime. Each value has an explicit env override;
the SDK-resolved value is the default.

| What | SDK resolution | Env override (default) |
|---|---|---|
| Own listen port | `codefly.For(ctx).Endpoint("http").NetworkInstance()` — the Codefly-assigned port, not a fixed default | `PORT` |
| Gateway URL (auth-gateway `rest`) | resolved by role — the single module owning the `auth-gateway` `rest`/`rest` endpoint, discovered from the injected carriers (or the workspace, run locally). Must be `https` | `GATEWAY_URL` |
| Credential mint URL | **not resolved — required explicitly.** Must be `https`. Nothing derives it: whether the host mints through the gateway or the workload posts straight to the issuer is unsettled and neither endpoint is deployed, and this is the address the projected service-account token goes to, so an assumed one is refused at boot. Every boot logs where it will mint, and a 404 there means that endpoint does not exist on that host — not that this build was refused | `CODEFLY__CREDENTIAL_MINT_URL` (**required**) |
| Projected service-account token | `codefly.For(ctx).WorkspaceConfiguration("workload-identity", "TOKEN_FILE")` — a **path**, re-read at every mint | `CODEFLY__WORKLOAD_TOKEN_FILE` |
| Workload identity certificate | `workload-identity`/`CERT_FILE` | `CODEFLY__WORKLOAD_IDENTITY_CERT_FILE` |
| Workload identity private key | `workload-identity`/`KEY_FILE` | `CODEFLY__WORKLOAD_IDENTITY_KEY_FILE` |
| Peer trust anchor | `workload-identity`/`TRUST_BUNDLE_FILE` — **required**: the listener requires and verifies a caller's certificate against it, and the outbound client verifies the platform against it | `CODEFLY__WORKLOAD_IDENTITY_TRUST_BUNDLE_FILE` |
| Allowed callers | `workload-identity`/`ALLOWED_CALLERS_FILE` — **required**, a **path** to a file of identities, one per line (normally the gateway's); re-read per handshake. Verifying against the anchor says a caller holds an identity the platform issued; this says which of them this solution serves | `CODEFLY__WORKLOAD_IDENTITY_ALLOWED_CALLERS_FILE` |
| Credential mint peer | `workload-identity`/`MINT_PEERS_FILE` — **required**, a **path** to a file of identities; re-read per dial and per connection check | `CODEFLY__WORKLOAD_IDENTITY_MINT_PEERS_FILE` |
| Gateway peer | `workload-identity`/`GATEWAY_PEERS_FILE` — **required**, same shape. One set **per destination**: the mint and the gateway are two parties, and a single set spanning both authorises each to stand in for the other at the other's address — and the mint is the destination that receives the projected service-account token. A dial to an address that is neither has no set and is refused. When the two are at the **same** host and port — the brokered shape — a dial there cannot be attributed to one of them, so it is held to the **intersection** of both sets, and an empty intersection is refused at boot | `CODEFLY__WORKLOAD_IDENTITY_GATEWAY_PEERS_FILE` |
| Principal this workload runs as | `module-authority`/`PRINCIPAL`, read once and frozen | — |
| Audience it mints against | `module-authority`/`AUDIENCE`, read once and frozen | — |
| Audience of its own projected token | `module-authority`/`PROJECTION_AUDIENCE`, read once and frozen | — |
| Contract profile | the Codefly environment's own name, which is how Core resolves a profile for an environment that declares none | `CODEFLY__CONTRACT_PROFILE` |
| MF assets | `Manifest.Assets` when set (see below), else the `../fe-remote/dist` directory | `ASSETS_DIR` (directory only) |

Every `workload-identity` value is a **path, never material**, the three
admission sets included — and that is what makes them live. They are admission
decisions, and an admission decision read once at boot cannot narrow: removing a
compromised identity from either file takes effect on the next handshake, the
next dial and the next connection check, with no restart. A set that resolves to
nothing, or that cannot be read, **refuses** rather than falling back to the set
the process booted with.

> They were configuration *values* until round four of review, re-resolved on
> every handshake through the SDK's accessor — which does not work and this
> README claimed it did. A configuration value, inline or file-carried, is fixed
> at process start (the SDK reads the file once and keeps it, `file_carrier.go`),
> so the re-resolution returned the boot answer for the life of the process, the
> refusal branch was unreachable in any deployment, and revoking a caller
> silently needed a restart. They are paths now, read by this process like the
> trust anchor beside them, which is the only form that can be what was
> documented.

The files behind these paths are read by this process — the token at every mint,
the key pair and the anchor at every handshake, the two admission sets at every
handshake and dial — so the SDK's value accessors are the wrong tool for any of
it: a file-carried configuration value is read once and kept for the life of the
process, which is right for a configuration value and wrong for anything the
platform changes underneath one.

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

**Removed in this cutover, with the registrations they fed**: `PUBLIC_URL`,
`SELF_UPSTREAM`, `HOST_REGISTER_URL`, `GATEWAY_REGISTER_URL`,
`GATEWAY_MODULE_REGISTER_URL`, `GATEWAY_MODULE_REGISTRATION_TOKEN_URL`,
`GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL`, `CODEFLY_INTERNAL_TOKEN`,
`CODEFLY__SOLUTION_REGISTRATION_SECRET`, `CODEFLY__MODULE_REGISTRATION_SECRETS`,
`CODEFLY__SOLUTION_REGISTRATION_INTERVAL`, and `CODEFLY_HOST_FRONTEND`. Setting
any of them now does nothing. Nothing reads the shared cluster-internal token or
a per-solution registration secret any more: the credential this runtime
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

## The workload identity

The listener presents the X.509-SVID issued to this workload, over TLS 1.3, and
there is no plain-HTTP listener. A configuration that cannot produce an identity
is refused at boot, naming the missing material: a solution that came up on
plain HTTP would be refused at the edge instead, for a reason only the edge can
see, which is the failure the delivered-presence model exists to end.

The default source is the pair the platform projects at the two paths above,
read through the SDK's certificate reloader: it re-reads the files when they
change and keeps serving the last good pair through a half-written replacement.
That matters more here than anywhere else, because workload leaves are
deliberately short-lived and rotated well before expiry — a process that loaded
its leaf once at boot serves a stale leaf while a valid one sits on disk, and
then fails every handshake with the issuer reporting nothing wrong.

Issuing an identity is the platform's job, not this runtime's, so the source is
a hook:

```go
solution.New(manifest).Identity(mySPIFFEWorkloadAPI{}).Serve()
```

An `IdentitySource` returns the `*tls.Config` the listener serves with, so an
issuer with its own rotation, revocation or peer-verification rules keeps them.
A source that returns no certificate is refused rather than started: a listener
that completes no handshake reports a TLS error naming nothing to every caller.

**The listener authorises its callers, not merely authenticates them.** Every
workload in the trust domain holds a certificate from the same anchor —
including the modules this solution consumes — so verifying one answers "did the
platform issue this identity", not "may this caller call me". The admitted set
is therefore declared and provisioned (`workload-identity`/`ALLOWED_CALLERS_FILE`)
and the boot is refused when it is absent, naming the value; the comparison is
the SPIFFE ID in the caller's URI SAN. Without it a consumed module could call a
handler or a passthrough route directly, bypassing the admission the host
decides on its own routes, and — because `x-org-id` and `x-session-id` are read
as headers the gateway stamped from a verified bearer — set them itself and have
this runtime mint capabilities under its attestation for an organization and
session nobody authenticated. A confused deputy, where the deputy is the one
process the issuer trusts to say which module is asking. The refusal names the
identity that arrived and never the admitted set.

**The listener authenticates its callers, and so does the identity it presents
outward.** It requires and verifies a caller's certificate against the projected
anchor — not optionally, and not when one happens to be configured: a listener
that verifies no peer accepts anything that can route to the pod, which bypasses
the admission and exposure decisions the host makes on its own routes. An absent
anchor is a boot refusal naming the value; an unusable one fails the handshake
rather than falling back, because judging callers by a stale anchor lets in who
should be refused, which is not symmetric with serving a stale leaf. Peer trust
is re-read **per handshake**, so removing a compromised root from the bundle
stops it authenticating new callers without a restart.

And every **established** connection is re-verified too, once a second, in both
directions — the caller's chain against the current anchor and the current
admitted set, the platform's against the same. Re-reading trust per handshake
bounds nothing about a connection that has already handshaken: a caller removed
from the admitted set, or whose issuing root was pulled, kept the keep-alive
connection it already held and kept being served on it, and so did an outbound
connection carrying a request every 100ms. An idle timeout cannot bound a
connection that is never idle. A connection whose peer stops verifying is closed
— busy or idle, request or stream — and nothing else closes it: a failure to
re-read *this* workload's own key pair is not a judgement about the peer and
leaves established connections alone. The listener also sets a handshake and
header deadline and an idle timeout, so a peer that connects and then stalls
mid-`ClientHello` no longer holds a goroutine and a descriptor indefinitely;
neither bounds a whole request, because a declared long-running stream is
conforming traffic.

**A consumer's `IdentitySource` that sets `GetConfigForClient` must implement
`PeerAnchorSource`** — whatever it carries on the base configuration. Re-verifying an established caller, and
verifying the platform this runtime dials, both need the anchor *as it is now* —
and if the only way to get it is the source's `GetConfigForClient`, the runtime
would have to call it with a `ClientHelloInfo` nobody sent. That is the defect
this cutover was already blocked on one field along: a source keyed on the hello
answers a synthetic probe with one thing and the real handshake with another,
demonstrably. So the source is asked directly —
`PeerAnchor() (*x509.CertPool, error)` — and one that can only answer through a
handshake is refused at boot. Carrying a pool on the base as well does not
answer it: that pool is one object fixed when the source built it, so it would
freeze the anchor this process judges by while the callback went on resolving a
fresh one — which is exactly what happened when the refusal only fired on a nil
base pool. A source with no callback at all may carry its anchor on the
configuration and needs nothing extra. The projected source implements the
interface.

Nor may a source set `VerifyPeerCertificate`: it is handed the parsed chain this
runtime reads the caller's identity from, and it runs first, so a source that
rewrote the leaf's URI SANs decided who was admitted. The identity is read from
a fresh parse of the raw DER regardless — the bytes the peer signed are the only
thing that cannot be edited between the handshake and the check — and the field
is refused as well.

The same fabrication is still used for the outbound **certificate**, and that is
sound for a reason worth stating: whatever comes back is held to the frozen
principal at the moment it is presented, so a source answering differently from
the real handshake is caught by that hold. An anchor has no check behind it — it
*is* the check.

**An outbound TLS handshake carries its own 10-second deadline.** A custom
`DialTLSContext` takes `net/http` out of the handshake, so
`Transport.TLSHandshakeTimeout` does nothing and the only bound would be the
caller's context — which is right for a request and wrong for the one place it
matters, since the client that carries streams sets no timeout on purpose. A
handshake is not a stream.

**An admission set answered twice is refused, not ranked.** The env override and
the platform's provisioning are two sources for one authorization fact; if both
answer, the boot fails naming both. Logging which one won reports the conflict
without resolving it, and for admission the cost of picking wrong is admitting a
caller. The other `workload-identity` paths still take the override first: the
worst case there is this process reading its own material from elsewhere.

**This listener does not resume TLS sessions.** A resumed connection presents
**no certificate** — the peer is accepted on a ticket — and this listener's
whole model is that a caller's certificate names them and the provisioned set
decides whether that name may call. So anything able to forge a ticket is able
to be admitted as whoever it was issued to. A review demonstrated it: with a
source-supplied ticket key, a client holding only that key and an admitted
caller's ticket resumed as that caller, presenting nothing, and the per-second
recheck then re-verified the stolen certificate and kept the connection open.
A denylist could not close that, because `SetSessionTicketKeys` installs keys
that cannot be read back off the configuration — so resumption is turned off on
the configuration served and on every per-connection answer. It costs one round
trip on a reconnect.

**An admission entry must be a whole line.** The file is read per handshake and
per dial, so it is read while the platform may be rewriting it: a file caught
mid-write truncated an entry, and the truncation was admitted as an identity of
its own (`…/sa/gateway-internal` read as `…/sa/gateway`, admitting a caller the
set never named). A file that does not end in a newline is refused, every entry
must be a SPIFFE ID, control characters and a byte-order mark are refused, and
the file is capped at 64 KiB because it is re-read once a second per established
connection in each direction.

**A credential-bearing URL carries a destination and nothing else.** Userinfo, a
query and a fragment are refused at boot on both the gateway and the mint:
credentials in a URL are a secret that gets logged and, for userinfo, that
net/http strips before the request is sent, so it is disclosed and never used.
Both URLs are logged through `url.Redacted()` with the query dropped regardless,
because a log line is the wrong place to depend on a check that runs elsewhere.

**No credential-bearing request follows a redirect, and none leaves the
gateway's own origin.** Go copies a request's headers onto a redirected one and
strips only `Authorization`, `WWW-Authenticate` and `Cookie`; a 307 re-sends the
body; and this runtime sets the bearer per round trip, which puts back the one
header Go strips. So a single `307 Location: http://elsewhere/` would hand a
third party the viewer's bearer, the capability minted for them and this
workload's own credential, in cleartext — nothing about an `http://` hop involves
the TLS configuration that protects the first one. Every client is therefore
built with `ErrUseLastResponse` (a 3xx is reported, never taken), and the
transport refuses any destination that is not the gateway's origin, so a client
built later without the policy is still stopped.

**Outbound trust is re-read per connection, not snapshotted at boot** — the same
rule as inbound, for the same reason, and it applies with more force: the two
destinations on the other side of that client receive the projected
service-account token, the viewer's bearer and this workload's own credential, so
a root removed because it was compromised must stop authenticating them without a
restart. Each dial builds its own configuration — and each
established connection re-verifies the peer it already has, once a second,
against the current anchor and the current the destination's own provisioned set, closing it when
that stops holding.

The recheck is there because the idle cap it replaces was not a bound. An
inactivity timeout bounds a connection nobody is using; a connection carrying a
request every 100ms never becomes idle, and one was demonstrated still answering
31 seconds after its server's root was removed from the bundle, over a single
handshake. A stream is the same shape by construction, held open for as long as
its declared `MaxStreamDuration` allows. Re-verifying rather than imposing a
maximum connection age is deliberate: a maximum age would cut a conforming
30-minute stream to answer a question that can be answered without cutting it,
since the chain the peer presented is already in hand. A peer that no longer
verifies loses the connection, in flight or idle, stream or request.

**And the destination is authorised, not just authenticated.** Verifying the
chain and the hostname says the cell issued a certificate for the address this
runtime dialled, which every workload in the cell holds one of — a neighbouring
workload answering at the gateway's address under a valid certificate was handed
the projected token, the viewer's bearer and this workload's credential. So the
peer's own SPIFFE ID must be in that destination's provisioned set. The outbound leaf is held to
the frozen principal too, at the moment it is presented, which matters because
on the default path it comes from a second reloader over the same files as the
listener's.

The same identity goes out. Every platform request — the mint, and every call a
handler's gateway makes — presents this workload's X.509-SVID and verifies the
far end against the same anchor, because an `https` URL on its own says only
that the scheme is https: without an anchor the far end is checked against
whatever the image's system roots hold, and without a client certificate it
cannot tell this workload from anything else that reached it. Nothing is
proxied, and no redirect is followed.

**The certificate served is the certificate checked.** The pair the platform
projects and the principal it provisioned are two facts nothing else compares,
so this runtime compares them: the SPIFFE ID in the leaf's URI SAN must equal
`module-authority/PRINCIPAL`. A pair projected for a neighbouring workload — the
wrong Secret mounted, a Certificate issued for another service — would otherwise
be served happily, and the mismatch would surface at whatever verifies this
destination, as a refusal naming neither file.

The comparison is made on the pair a handshake actually selected, not on a
sample. A boot-time check that called `GetCertificate` once and approved the
configuration was demonstrated passing four configurations that then served
another workload's leaf: a callback keyed on the server name answering a probe
and a real hello differently, a `NameToCertificate` map, a static
`Certificates[0]` that Go reaches without consulting the callback at all when
the caller sends no SNI, and a `tls.Certificate.Leaf` that did not describe its
own DER. So the selection surface is narrowed to one certificate (a
`NameToCertificate` map or a list of several is refused — a workload has one
X.509-SVID), the DER is parsed rather than `Leaf` believed, and the callback is
wrapped so that what it returns for this handshake is what is compared. A
boot-time refusal remains, asked with the empty hello a peer addressed by IP
really sends, and it can only refuse a boot — never approve one.

Every one of those applies to a consumer-supplied `IdentitySource` too, checked
on what it returns: a certificate, a TLS 1.3 floor, and a caller it
authenticates. Checking only that a certificate came back left the floor and
peer authentication silently optional for exactly the consumers who wrote their
own integration.

It is checked **per connection** as well as at boot. A `*tls.Config` may carry a
`GetConfigForClient` callback, and the configuration that callback returns
replaces the base one for that handshake — floor, peer requirement and
certificate included — so a source that conforms at boot could answer each
individual connection with TLS 1.2, no peer authentication, or a neighbouring
workload's leaf. This is the documented shape here rather than an odd one: the
projected source uses that callback to re-read peer trust. So each returned
configuration is held to the same posture and the same frozen principal, and one
below it fails that handshake instead of serving it weakened. A callback that
returns `nil` is Go's "serve the base configuration", and passes through only
when that base really satisfies the posture on its own: a source answering for
one hello and not another was otherwise serving a listener that requires a
caller's certificate and verifies it against the host's system roots, which is
mutual TLS in every log line and a client certificate from any public CA
admitted.

## One credential per execution

`Serve` obtains this execution's credential once, before the listener exists,
through the SDK's mint client (`sdk-go/workcontext`): the projected
service-account token is presented to the host's mint endpoint, and the host —
which establishes the principal, the installation and the build from that token
and its own records, never from anything this process reports — answers with a
credential sealed to this build incarnation and this installation.

The runtime holds no mint of its own and runs no timer that is not the
credential's own expiry. Every use goes through the client, which hands back the
credential it holds while that one is current and renews it once it has entered
its renewal lead, re-reading the rotated projection and rechecking the frozen
authority values first. A process that runs for a week under credentials the
issuer chose to make long-lived mints once and renews a handful of times; it
never mints per beat or per probe, and does not mint per request: acquisition is
single-flight, a failed ask quiets the next ones for a second, and a credential
already in hand and unexpired is what serves meanwhile. That last part is not a
detail — renewal begins inside a lead *before* expiry, so refusing while the
issuer is slow would answer 503 to every viewer over a dependency this process
does not yet need. A route gate that asked per request turned a 503-ing issuer
into one audited mint per request, which is worse than the heartbeat this
runtime replaced, because the heartbeat at least minted on a timer.

**A refused first mint fails the boot and is never retried. An unavailable one
is waited for, within a bound.** The two are different answers:

- a **refusal** (`ErrMintRefused`, the host's `403`, or `404` from a host that
  serves no mint) is the issuer judging this workload: this build is not the one
  its presence document approved, the pod's identity does not match, the token
  attests to another subject. No number of attempts changes any of those
  answers, so the boot reports what the issuer said and exits non-zero. A loop
  around it is what this change exists to delete: the old runtime answered every
  refusal by beating again, minting a fresh single-use token each time, so one
  undeployable solution produced an audited mint every 15 seconds for as long as
  it ran.
- an **unavailable** mint (`ErrMintUnavailable`, the host's `503`, `429` or
  other `5xx`) is not a judgement. A workload may legitimately start before its
  presence generation has been applied, and then there is no incarnation to mint
  against yet; the issuer may also be unable to reach the Kubernetes API or its
  own policy log, and a host that issues nothing in those cases is behaving
  correctly. So the boot asks again, backing off, for up to **two minutes**, and
  then exits non-zero.

The bound is what keeps the second case from being the heartbeat again: it is a
boot waiting for a dependency, with no steady state, nothing minted on success
beyond the one credential, and an exit — the orchestrator's cue to restart —
when it is spent.

The credential is also what this runtime presents on the mint it runs **for a
viewer** (see [Reading a Work-Context-authenticated
module](#reading-a-work-context-authenticated-module)): the viewer's bearer says
on whose behalf, and this credential says which module is asking, so the issuer
can hold that mint to the installation and binding the credential is sealed to
instead of seeing only that somebody holding a viewer's bearer asked.

**A mint this runtime cannot attest for is not sent.** If the credential cannot
be obtained — no source, a refused renewal, authority that drifted, a capability
that cannot be attached — the call is refused with `ErrNotAttested` and the page
sees `unavailable`: the viewer's own authority is not in question and one
renewal fixes it.

It used to log and carry on, and that was wrong in the one case the attestation
exists for. The issuer stops renewing precisely when the installation has moved,
the build is no longer approved, or the principal's epoch has advanced — so a
workload in exactly that state kept minting viewer capabilities with no
execution binding on any of them. "The host does not require the attestation
yet" is a statement about the counterpart's current state, and boot-time
approval is not authorization at use. The refusal is logged once per distinct
failure rather than once per request, and once more when it recovers; what a
caller gets is not throttled, because every affected call is refused.

A capability the far end reports as **superseded** (its sealed state has moved)
is dropped from the request's cache rather than reused until its own clock runs
out, so the next call mints instead of presenting a credential the issuer has
stopped honouring.

A consumer whose issuer is reached another way supplies its own source:

```go
solution.New(manifest).Credential(mySource).Serve() // Credential(ctx) (workcontext.Credential, error)
```

### This runtime neither signs, parses nor verifies a capability

There is **one** implementation of a Work Context — Core's (`core/workcontext`:
deterministic proto, Ed25519) — and this runtime is not it. It obtains a
credential through the SDK's client, carries it as the string it travels as,
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
all 21 fixtures are offered to the carrier, and each one's refusal is attributed
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
binding) — is reported as `aborted`, because the answer to every one of those
is to mint again rather than to retry or to tell the viewer their authorization
failed. `ErrInvalid`, `ErrUnsealed` and `ErrNotACoreToken` are reported as
`internal`: a credential this solution could not present is this solution's
problem, not a module that is briefly unreachable.

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
- The **upstream the gateway dials** is in the presence document, not in a
  registration. `SELF_UPSTREAM` and the self-endpoint carrier it fell back to
  are gone. A deployed solution used to register its own loopback listen
  address, boot, look healthy, and be proxied by the gateway to the gateway
  itself while the product reported it as failed to load; the refusal that
  caught that is gone with the registration that needed it.

This solution still publishes what it is, at fixed paths, for anything that
asks: `/.well-known/solution.json` (the manifest: nav, the exposed module, the
federation manifest path, the backend's service alias, declared surfaces and an
optional dashboard), `/.well-known/capabilities` (the contract id and the
majors), `/.well-known/module-contract` (the authority contract above) and
`/health`. Publishing is not announcing — nothing is pushed, and answering
makes this solution present to nobody.

`/health` **asks the credential** rather than reporting only what some other
request happened to discover. Renewal is lazy by design, so a solution serving
only ViewerBearer routes, plain handlers and assets would otherwise never ask and
never learn that the issuer had stopped approving its build. Asking is not a
heartbeat: the client holds one credential and returns the same one until its own
renewal point, so a probe is a mutex and a comparison except at the renewal the
credential's expiry dictates. A credential that cannot currently be obtained is
503 and nothing ends; a refusal is 503 **and** ends the process.

So `/health` answers 200 while this process can do its job, and **503 once the
issuer has refused this execution's credential for good** — `ErrMintRefused` at
renewal, which is a judgement about this execution that no retry changes.
(`ErrRevoked` is not one of these: it never comes back from the mint, only from
a callee rejecting a capability this runtime minted for a viewer, which is a 409
on that request.) The process then stops serving and returns that reason, for the
orchestrator to restart it against the delivery as it stands. An unconditional
200 was wrong in exactly the case the probe exists for: the boot already treats a
refusal as terminal, while at renewal the same judgement reached a page as
"unavailable, one renewal fixes it", so a solution would answer 503 to every
request forever and report itself healthy throughout — a solution that serves
nothing and looks alive, which is what the delivered-presence model replaced the
heartbeat to avoid. An *unavailable* mint is not a judgement and deliberately
does not do this: exiting on a transient dependency failure is a crash loop.

The manifest declares the contract majors it is built against
(`schemaVersion: 1`, `frontend.hostContract: 1`) rather than leaving a reader to
assume them, and the capability document declares the same majors from the same
constants — so a bump cannot leave one document announcing the old major while
the other announces the new one.


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
deleted, along with `CODEFLY__MODULE_REGISTRATION_SECRETS` and the per-module
secrets it carried.

Codefly still projects the targets into `CODEFLY__API_CONSUMES`, and that
projection is still what the passthrough declaration is checked against — at
boot, resolved like every other value, so a malformed one is a refusal rather
than a log line. It used to be read at serve time: a malformed projection
disabled the whole federation with one log line while the solution served on,
so every consumed facade 404'd at the gateway and the solution looked healthy.


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

`Serve` resolves the gateway and api.consumes from the composition, mints this
execution's credential and listens with this workload's identity, so a solution
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
| `Host.RefuseMints(func(Mint) *Refusal)` | Decides each mint: a non-nil `Refusal` refuses it as accounts would (default status 403), so the page sees `permission_denied` with its message. |
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
the mTLS boot, the caller allow-list, the published ceiling and authenticated
outbound — a deployment calling it completed a viewer mint and a module call
over plaintext and answered 200, with the viewer's bearer and this workload's
own credential on the wire. Supplying a credential source, which a deployment
does, defeated the "no source, nothing to mint with" mitigation. It is reached
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

> **Note on pins.** SDK in-process endpoint resolution for a solution composed
> on an out-of-repo host depends on codefly-core accepting the composed module
> path in its workspace loader (codefly-dev/core#365, merged); the
> configuration-profile rule and `core/workcontext` come from core; and the
> certificate reloader, the authority reader and the mint client come from
> sdk-go. The `core` and `sdk-go` pins in `go.mod` carry all of it, and there is
> **no `replace` directive** — both are ordinary pseudo-version `require`s, so
> this module builds from its own tag for anyone.
>
> Those two pins are currently unreleased branches (core#692 and
> codefly-dev/sdk-go#48, the Work Context single-implementation fix) and must
> move to the releases at merge, core first. Every capability's format changes
> in that cutover, so verifiers upgrade before minters or calls fail closed in
> the window.
