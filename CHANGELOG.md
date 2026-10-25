# Changelog

## Unreleased — review fixes for #75: the authority is asked about the operation dispatched (breaking)

From the independent review of #75 (r1):

- **The route checked is the operation dispatched (F1, security; F2).** The
  authority was asked about `r.Method + " " + r.URL.Path`, the decoded path,
  while the mux dispatches on the escaped one: `GET /v1/page/pages/secret%2Fhistory`
  ran the `/pages/{id}` operation and was checked against the
  `/pages/{id}/history` row, so a caller holding only the weaker history row
  ran the page handler. The same root made a subtree `/x/` beside `/x/{id}`
  (legal for the mux) a path the authority refuses as matching two routes.
  `wrapRequest` now asks about the dispatched operation's own row,
  `"<VERB> " + servedRoute(path)`, which the authority finds by exact name.
- **`InterfaceInfo.BasePath` is deleted (F4).** The CLI prefixes every route
  row with the document's base path, while the edge forwards a solution's
  requests on `/v1/<id>` and the runtime checks routes as served, so no
  non-empty base path ever matched a request. A backend still setting it no
  longer compiles, naming the field: drop it and carry `/v1/<id>` in each
  operation's path, as the migrated solutions do.
- **A malformed request is refused with its reason (F5).** An
  `InvalidArgument` or `OutOfRange` from the authority's `Check` is answered
  400 (`invalid_argument` on a relayed call) with the authority's reason,
  `ErrRequestInvalid`, never 503 "try again"; an issue refused that way is a
  `WorkContextRefusal` of 400 with its reason.
- **A stream's first message is bounded again (F6).** A relayed
  server-streaming call cuts off a module that accepts the stream and sends
  nothing at the method's `Timeout`, as `StreamFirstAnswerWithin` did before
  the authority move, instead of holding it for the whole `MaxStreamDuration`.
- **Open (F3):** `go.mod` pins the authority client and hop libraries at
  commits only on the unmerged `authority/vision` branch. This closes when
  authority#1 merges with a merge commit and this runtime re-pins; no runtime
  release before then.

## Unreleased — the operation checked is the operation run; every served route publishes its policy (breaking)

From the independent review of 2026-10-25 (F1–F4, F10, F11):

- **Dispatch by method and path (F1, security).** The runtime picked a
  handler by path alone, so with a GET (read policy) and a POST (write policy)
  on one path, a GET checked against the read row ran the POST handler. A
  request is now answered by the operation declared for its method on its
  path, which is the operation the authority's `Check` names; a method the
  path does not declare is answered 405, naming the methods it serves (and
  `Allow`), before the authority is asked or any handler runs. The boot
  refuses an operation that declares no policy, is undocumented, declares one
  method twice on a path, or names a method that is not an operation's.
  `Server.Handle` and `Server.HandleRequest`, which registered a route with
  no method and no policy, are deleted: `Operations` is the one way a backend
  serves a route of its own.
- **Issues go through the authority's hop library (F2).** `ForParent` and
  `ForBinding` ask through `hop.Outbound.IssueForParent` / `IssueForModule`
  (codefly-dev/authority `libraries/hop/go`, extended for it) with
  `hop.FileCredential` at the projected path; the runtime builds no
  `IssueRequest` and reads no credential file of its own.
- **The MCP route publishes its policy (F3).** `ServeMCP(name, version,
  policy, register)` takes the policy a call to `POST /v1/<id>/mcp` must hold,
  and the interface artifact publishes it there, so the CLI's rows include the
  route and an enforcing authority admits it. Only POST is served.
- **Relayed routes are any checked caller's (F4).** Every relayed
  `/v1/<id>/modules/<as>/...` route is published with
  `{"any_checked_caller": true}` and the passthrough's `Check` names it as
  served; the gate on a relayed call is the per-call child issued through the
  solution's binding (the person's current grants ∩ the binding) and the
  module's own method policy at its hop. The README says why. A route refusal
  reaches the page as `permission_denied`.
- **`InterfaceArtifact` is the server's (breaking).** `Server.InterfaceArtifact(dir,
  info)` renders the artifact from what the server serves — its operations,
  its MCP route and the passthrough at the paths they are served at — so a
  route cannot be served without a row. The free `InterfaceArtifact(dir, info,
  ops, modules...)` is deleted.
- **An authority outage is named (F10).** A `Check` the authority did not
  answer is 503 `ErrAuthorityUnavailable` (Connect `unavailable`), never a
  401 that reads as "sign in".
- **The authority endpoint passes the SDK's credential-destination rule
  (F11).** It is dialled through the same `workcontext.AdmitEndpoint` rule as
  every relayed module.

## Unreleased — the runtime runs only under the authority; the saas-host mode is deleted (breaking)

Since the passthrough relays only through the authority, nothing a consuming
solution does reaches the saas host any more, and the rest of that mode is
deleted with its tests and docs:

- `Gateway.ForModule` and its published-ceiling check, the accounts
  `StartTask` mint, and the identity headers it was rooted in
  (`Gateway.InstallationID`, `x-org-id`, `x-session-id`,
  `x-codefly-installation-id`).
- The broker execution credential: `Server.Credential`, `CredentialSource`,
  the `module-authority` group (`AuthorityGroup` and its keys,
  `INTERNAL_TOKEN`), the per-installation credential controller, and the
  `saas-sdk-go` dependency.
- Calls through the saas gateway: `Gateway.Transcoded`, `MaxResponseBytes`,
  `TranscodeOption`, `DefaultTranscodedResponseLimit` (now
  `DefaultPassthroughResponseLimit`), `Unary`, `Gateway.HTTPClient`,
  `Gateway.BaseURL`, gateway resolution by role (`GATEWAY_URL`,
  `CODEFLY_HOST_MODULE`, `CODEFLY_HOST_GATEWAY`, `CODEFLY_HOST_FRONTEND`).
- The install step: `Server.OnInstall`, `Installation`, `RefuseInstall`,
  `ErrInstallRefused` and `POST /_codefly/installations`.
- The MCP surface's saas wiring: the gateway-stamped identity it read, the
  OAuth Protected Resource Metadata document and its challenge,
  `ProtectedResourceMetadataPath`, `MCPEnvironment`, the `mcp` group
  (`issuer-url`, `public-url`) and `PUBLIC_URL`.
- `ErrNotAttested`, `ErrCredentialRefused`, `ErrCredentialUnavailable`,
  `WorkContextPrincipals` from an accounts mint, and the published
  contract's `principal`.

Kept, because the authority path reaches it:

- `ServeMCP` and `ViewerFromContext`: the MCP transport, now served at
  `/v1/<id>/mcp` and admitted exactly as a handler route is — the authority's
  `Check` of the Work Context the request carries, naming `POST /v1/<id>/mcp`.
  A tool reaches a module through `ForParent`. This is the transport an
  authority-based MCP route (robin calling a solution's tools) builds on.
- `Contract`/`ModuleContract`/`ContractArtifact`: optional; a solution that
  declares no ceiling is bounded by the authority alone.
- `GatewayError`, `ClientError`, `WorkContextRefusal`: a handler's own
  refusals and the authority's.

A composition that names no `authority/endpoint` is now refused at boot,
whether or not the solution consumes modules, and so is one with no projected
workload credential path.

## Unreleased — the passthrough relays only through the authority, by each module's own procedure (breaking)

The passthrough relays every declared method over gRPC to the module's own
procedure — the Connect/gRPC face the module serves behind the authority's
hop — so a module whose protos carry no `google.api.http` binding is consumed
as it is. No binding is read: the boot no longer requires one under
`/v1/<as>` for every declared method, which refused every solution pinned to a
module that serves only behind the hop. A server-streaming method is relayed
as a gRPC stream, bounded and masked as before.

The saas-host passthrough is deleted, with its configuration, tests and docs:
forwarding a method over its REST binding through the saas gateway (`forward`,
the NDJSON stream reader and `Gateway.TranscodedStream`, `StreamError`,
`ErrStreamMessageTooLarge`, `StreamOption`), `ConsumedModule.ViewerBearer`,
the check of the declaration against the `CODEFLY__API_CONSUMES` projection
(which is no longer read), the plain-text gateway refusal relay, and the test
seam that faked the saas host (`passthroughtest`, `internal/seam`).

- `ConsumedModule.Authority` is required on every consumed module, naming all
  three of its group, endpoint slot and binding slot.
- A solution that declares consumed modules and has no `authority/endpoint`
  refuses to boot, naming it — before the gateway, which its page's calls
  never reach. The `module-authority/INTERNAL_TOKEN` refusal it replaces is
  gone, and so is the boot's broker credential for a consuming solution in
  saas mode, which this made unreachable.
- `GatewayError` keeps only its status: the refusal body it carried was read
  by the saas passthrough alone.

## Unreleased — every documented operation declares its authority policy (breaking)

`Operation.Policy` is what a call to the route must hold —
`Requires(kind, actions...)` or `AnyCheckedCaller()`, the shape of the
authority's `authority.hop.v1.Policy` — and `InterfaceDocument` writes it as
the operation's `x-codefly-authority-policy`, the extension the CLI derives
the solution's `"<VERB> <template>"` route rows from. An operation that
declares no policy, an empty one, or both, is refused at generation, by its
route: the runtime's `Check` names every route a request calls, so a route
with nothing to be held to would only ever be refused by the authority.

The document is written as the backend serves it: an empty `BasePath` is
omitted (an authority-served backend's operations already carry `/v1/<id>`),
a subtree pattern ending in `/` is written `/…/{path=**}`, and two methods on
one path are both kept (the second used to replace the first); one declared
twice is refused. The passthrough's documented routes carry no policy: the
module they relay to applies its own.

Each `operationId` is derived from the method and the route as served
(`<prefix>_<Method>_<Path…>`, GET `/sources` is `Notes_Get_Sources`, a
subtree `/x/` ends `_X_Path`), so the methods of one path, and a path and the
subtree under it, no longer share one; two operations the derivation would
spell alike are refused at generation.

## Unreleased — under the authority, a route is held to the solution's delivered policy; a module's tool call acts for the person

The authority's `Check` of the Work Context a request carries now names the
route it calls, `"<VERB> <path>"` as the solution serves it — the spelling the
authority matches against the `"<VERB> <template>"` rows the CLI derives from
the published contract — so the solution's delivered per-route policy is
applied. Before, any context addressed to the solution reached every route. A
route the call does not hold is answered 403 with the authority's reason
(`ErrRequestRefused`); a context the authority does not check is still 401.
Under `hop/ENFORCEMENT=warn` the check is the authority's advisory one, as a
permissive hop's is: the route goes through and the refusal is logged. The
passthrough relay names no route; the module it relays to applies its own.

A module calling a solution route as a tool, with the child the authority
issued through its binding, is admitted like the edge's context, and the
handler's gateway says who it is for: `WorkContextPrincipals` answers the
person as owner and the module as current actor, and the new
`Gateway.ActorChain()` the whole chain, both from the authority's `Check`.

`dialAuthority` is unexported; the authority client moves to 06d0d3b for
`CheckRequest.advisory`.

## Unreleased — the passthrough under the authority; refusals keep their reason

Under the authority interface the passthrough is no longer refused at boot: a
consumed module whose new `ConsumedModule.Authority` names its configuration
slots (gRPC address, binding id) is relayed over gRPC as the viewer, a child
of the edge's Work Context issued through that binding, pinned and masked as
declared, at `/v1/<id>/modules/…`. The copies solutions carried of this relay
can be deleted.

`WorkContextRefusal.Reason` carries the authority interface's reason for a
refusal (a transport failure keeps none, and the saas broker's body is still
never retained); handlers and the passthrough relay it. A refusal from a
solution's own route reaches a Connect or gRPC client as a Connect error, code
and message, instead of `{"error": …}`, which Connect clients ignore; a plain
REST caller (no `Connect-Protocol-Version`) still gets `{"error": …}`.

## Unreleased — `Gateway.InstallationID` exposes the stamped installation

`Gateway` exposed `OrgID()` but not the installation beside it, so a handler
that needed the installation it serves either re-parsed
`x-codefly-installation-id` itself or took an id from the browser.
`Gateway.InstallationID()` returns the installation the gateway stamped, as the
runtime accepted it — the same value every `ForModule` mint names. It is empty
when the request carries none or the header is blank (which the runtime
refuses), and on an install step's gateway. Additive; no signature changes.

## Unreleased — a 4xx refusal reaches the page with its reason

The host gateway refuses a module route in `text/plain`, one line naming the
rule — "module is not installed for this organization". The relay only read
JSON, so the page was told the status word alone, "Forbidden", and a viewer who
needed a grant on the module's installation had nothing to act on. A 4xx body
that is short, single-line printable text is now the message.

A 5xx body is still reported by kind: `upstream connect error: 10.0.0.7:8080
refused` is written by an intermediary and names an internal address.

## Unreleased — the mint reports the registration's dynamic half; the runtime serves uninstalled

The mint body carries `upstream` (the advertised https origin, never the listen
address) and `manifest` beside `prefix`, bounded at 64 KiB at boot. A deployed
runtime context refuses a loopback origin.

`412` from the broker is "admitted, installed nowhere": the runtime serves its
install step and `/health` holding no credential, and asks again until one is
issued. A viewer's route still answers 503.

A projected token that is not there yet is unavailable, not terminal: a boot
waits for it inside the two-minute window, and a renewal keeps an unexpired
credential. One that is present and unusable stays terminal.

## Unreleased — native module-broker execution mint

Breaking API change: `WorkContextRefusal.Code` and `WorkContextRefusal.Message`
are removed. Use `StatusCode` (or unwrap to `GatewayError`) to classify failures.
Errors and passthrough responses no longer expose broker diagnostics.
No registration-secret API remains in the starting revision of this repository.

The projected token path defaults to `/var/run/secrets/codefly/token`; the CLI
mounts it read-only for audience `accounts` with a lifetime of at most 600 seconds.
The runtime reads the bounded file again before each mint. Missing, empty,
unreadable and oversized projections fail closed.

Execution minting now implements the published `saas-sdk-go/moduleauthority`
contract at `217bf9fe3f10` natively: `POST /modules/_work-context`, the declared
`Manifest.ID` as `prefix`, the fresh projected bearer, and the perimeter token
from the declared workspace secret `module-authority/INTERNAL_TOKEN`. The legacy
internal-token variable remains ignored. This is a runtime protocol fix; no SDK
package is vendored or copied and dependency pins are unchanged.

The broker client accepts the camel-case response and delegates structural
capability inspection to Core. The public `CredentialSource` signature is
unchanged. TLS identity, fresh trust/admission checks, frozen authority,
installation/build holds, single-flight acquisition and expiry-driven renewal
remain enforced.

Only 503 and typed timeout/connection-refused/connection-reset failures retry.
401/403 remain terminal refusals; every other status and permanent transport or
response error is terminal. Errors retain safe classification and discard raw
diagnostics. Conformance tests exercise the actual request and response using
an in-memory fake broker, including boot and renewal retry decisions.

The legacy-secret regression again sets nonempty deleted secret variables.
Compiler gates pin the canonical forbidden spellings independently of this
archive; compiled fixtures prove that reintroduced readers are rejected.

### Removed authentication configuration (archive)

These identifiers are deleted, not compatibility inputs:
`MODULE_IDENTITY_SECRET`, `MODULE_IDENTITY_SECRETS`, `MODULE_IDENTITY_PREFIX`,
`MODULE_REGISTRATION_SECRETS`, `SOLUTION_REGISTRATION_SECRETS`,
`CODEFLY__SOLUTION_REGISTRATION_SECRET`, `MintModuleRegistration`, and
`MintSolutionRegistration`.

These archived spellings are also independently pinned by the compiler-based
facade gate. Adversarial tests deliberately provision removed secrets.

| Kind | Removed wire spelling |
| --- | --- |
| header | `X-Codefly-Module-Secret` |
| carrier | `CODEFLY__MODULE_REGISTRATION_SECRETS` |
