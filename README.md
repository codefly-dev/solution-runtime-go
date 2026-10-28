# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns configuration
resolution, a plain-HTTP listener on the port Codefly resolves, CORS, Module
Federation asset serving, the capability handshake, the manifest served from
the declared frontend file, the published contract, the connection to the
**authority interface**, the passthrough that relays a page's module calls as
the viewer, and serving the solution's MCP server to agent clients.

A component author writes a manifest, optionally embeds a frontend, and
declares its operations — each one method on one path, the policy a call to it
must hold, and its handler:

```go
//go:embed solution.frontend.codefly.yaml
var frontend []byte

solution.New(solution.Manifest{ID: "my-solution", Frontend: frontend}).
    Operations(solution.Operation{
        Method: "get", Path: "/v1/my-solution/thing",
        Summary: "Read the thing", Callers: "Readers.", Behavior: "The thing.", Response: thing{},
        Policy: solution.Requires("my-solution.thing", "read"),
        Handler: func(ctx context.Context, gw *solution.Gateway) (any, error) {
            docs, err := gw.ForParent(ctx, "documents-read",
                solution.Scope{ResourceKind: "documents", Actions: []string{"read"}})
            if err != nil {
                return nil, err
            }
            token, err := docs.WorkContext(ctx) // present it to the module, over gRPC through the hop
            ...
        },
    }).
    Serve()
```

Every request reaches the solution through the authority's edge with the
person's Work Context, and every Work Context the solution acts under is issued
by the authority. What the host lists the solution under — title, nav order,
exposed module, host contract, dashboard, surfaces — lives in
[`solution.frontend.codefly.yaml`](#the-declared-frontend) beside the backend's
`service.codefly.yaml`, which the CLI delivers in the presence document and
this runtime serves its manifest from.

## The saas host is gone

This runtime used to run against the saas host as well: a bearer forwarded to
the host's gateway, a Task Work Context minted through accounts for the viewer
(`Gateway.ForModule`, with its ceiling check), an execution credential obtained
from the host's module broker (`Server.Credential`, `CredentialSource`, the
`module-authority` group), a module called over its REST binding
(`Gateway.Transcoded`, `Unary`, `HTTPClient`, `BaseURL`), the install step
(`OnInstall`, `Installation`, `RefuseInstall`), the identity headers the
gateway stamped (`InstallationID`, `x-org-id`, `x-session-id`), and the MCP
surface's OAuth discovery against the host's issuer. All of it is **deleted,
not fenced**: a solution that consumes modules relays them only through the
authority, and no path of the saas mode was still reachable. A composition
that names no `authority/endpoint` is refused at boot. Nothing bridges the two
models.

## A runtime does not register itself

Presence is **delivered**. A signed presence document declares which solution
runs on which host, at which generation and build, under which workload
identity; the host reconciles towards it. Health is **answered**, never
pushed: the host probes the destination its own presence document names, and
nothing this process answers can make it present. Boot and health ask the
authority nothing.

A solution used to become present by announcing itself — two
self-registrations on a 15s heartbeat, each burning an audited single-use
credential — which made presence a claim a process could make. That is gone,
with the endpoints that accepted it.

## Native listener isolation

On a local native run the runtime binds the loopback host and port of its own
SDK-resolved `http` endpoint. `PORT` can change the port, but cannot broaden the
listener to other interfaces. An absent or non-loopback native endpoint fails
configuration validation. The CLI supplies the endpoint automatically; there is
no separate host override to copy into each component.

Container and Kubernetes processes retain their container-wide listener, where
the platform owns network admission. A local environment name alone does not
turn a container listener into a loopback listener. Production admission still
requires the declared mesh boundary; this change does not qualify that boundary.

## Handler errors

Return `ClientError` for an explicitly public validation message. A Connect
error a handler returns — a module's answer to a call the handler made —
retains an actionable status: authentication 401, permission 403, missing
resource 404, invalid input 400, conflict 409, precondition 412, quota 429,
unavailable 503 and deadline 504. Other RPC failures return 502. Only generic
status text reaches the browser. An authority refusal (`WorkContextRefusal`)
keeps its status and the authority's reason. A transport failure never names
its destination. No request is retried or replayed.

REST adapters can return `&solution.GatewayError{StatusCode: resp.StatusCode}`
after a non-success response. The runtime preserves 4xx, 503 and 504;
unexpected statuses and other server failures become 502. This error carries no
raw body, URL or headers. Untyped errors keep the 502/public-error-string
behavior, so handlers must not put private details in them.

## The authority interface

The composition names the authority interface in workspace configuration
`authority/endpoint` (the authority gateway on a laptop, the host in a cell; see
codefly-dev/authority), and a boot without it is refused. The page is reached through the authority's **edge**,
the auth gateway's role: the browser's one origin, which signs the person in and
sends each request on with the person's Work Context addressed to this module
(`x-codefly-work-context`). The runtime holds no session bearer and mints
nothing:

- **Who a request is for**: the authority's `Check` of that Work Context,
  addressed to this module. `OrgID` is its organization; a header the request
  wrote about itself is ignored, and a request with no context, or one the
  authority does not check, is answered 401 before the handler runs. A module
  calling a route as a tool sends the child the authority issued it through
  its binding: `WorkContextPrincipals` names the person as owner and the module
  as current actor, and `ActorChain()` the whole chain.
- **Which routes it reaches**: the `Check` names the operation the request was
  dispatched to, `"<VERB> <template>"` exactly as its row is published, and
  the authority applies this module's delivered route policy (the
  `"<VERB> <template>"` rows the CLI derives from the published contract's
  `x-codefly-authority-policy`). The request's own path is never what is
  asked about: an encoded `/` in a segment (`/pages/a%2Fhistory`) runs the
  `/pages/{id}` operation while its decoded path reads as `/pages/{id}/history`,
  and a subtree and a `{id}` route the mux tells apart would both match it. A route the call does
  not hold, one that declares nothing, and one not served are answered 403
  with the authority's reason. Under `hop/ENFORCEMENT=warn` the check is
  advisory: the route goes through and the refusal is logged. An authority
  that cannot be reached refused nobody: the request is answered 503, naming
  that, never 401.
- **The operation checked is the operation run.** A request is served by the
  operation declared for its method on its path, and the `"<VERB> <template>"`
  the authority is asked about is that operation's, so it is the operation
  whose handler runs. A method the
  path does not declare is answered 405, naming the methods it serves (and
  `Allow`), before the authority is asked or any handler runs. The boot
  refuses an operation with no policy, an undocumented one, one method
  declared twice on a path, or a method that is not an operation's
  (`OPTIONS` is the CORS preflight the runtime answers).
- **`ForParent(binding, scopes...)`**: the viewer's own call to
  a module, a child of the edge's Work Context through one of this module's
  declared bindings, issued through the authority's hop library
  (`hop.Outbound.IssueForParent`, over the authority's generated client) with
  the workload credential the run attests as the actor. The authority derives the audience from the binding
  and grants within its invoke ceiling and what the person holds there; held
  until it is due for renewal.
- **`ForBinding(binding)`**: this module's own Work Context
  through one of its declared bindings, in the viewer's organization, with no
  person in it (`hop.Outbound.IssueForModule`). The runtime builds no issue
  request of its own: every Work Context it acts under is asked through the
  hop library, which reads the credential from the projected path on every
  call (`hop.FileCredential`).
- **`WorkContext(ctx)`**: the token a gateway acts under, for a caller that
  reaches a module itself — over gRPC through the hop.

- **The passthrough** (`Consumes`) is served from the same declaration, at
  `/v1/<id>/modules/<as>/<package.Service>/<Method>` (the edge routes a solution
  at `/v1/<id>` and forwards requests unchanged). Every consumed module's
  `Authority` names its configuration slots — the module's gRPC address, the
  hop in front of it, and the id of this solution's binding for it — and each
  call, unary or server-streaming, is relayed over gRPC to the module's own
  procedure as the viewer: a child of the edge's Work Context through that
  binding with the method's declared scopes, the pin merged in and the
  response allowlist applied. No `google.api.http` binding is needed. A
  missing slot refuses the boot. A solution that publishes no ceiling is
  bounded by the authority.
- **Every refusal names its reason.** The authority's reason for refusing an
  issue is kept (`WorkContextRefusal.Reason`), and a refusal reaches a Connect
  or gRPC caller as a Connect error with the authority's code — a Connect
  client reads nothing else — and a plain REST caller as `{"error": …}`.

The workload credential the authority takes as the actor of every issue is
the projected token at `/var/run/secrets/codefly/token` (overridden by
`CODEFLY__WORKLOAD_TOKEN_FILE`), re-read on every call because the projection
is rotated under the running process. Declare `module-identity` on the
backend so the run projects it.

## Configuration

On boot `Serve` calls `codefly.Init(ctx)`, which loads Codefly's injected
carriers and pins the module this process belongs to from `CODEFLY__MODULE`.
The SDK resolves no endpoint for a process it has not pinned, so a boot that
names no module — or a different one from the module the process was first
pinned to — is refused naming `CODEFLY__MODULE`. Then `loadConfig` resolves
every value through the codefly Go SDK (`github.com/codefly-dev/sdk-go`),
falling back to the local native workspace map when not running under the
runtime, and `validate()` refuses each one that is unresolved, naming the value
and the provisioning path that fixes it — including the difference between
"the SDK resolved nothing" and "loading the injected environment failed
first".

| What | SDK resolution | Env override (default) |
|---|---|---|
| Own listen port | `codefly.For(ctx).Endpoint("http").NetworkInstance()` — the Codefly-assigned port, not a fixed default | `PORT` |
| Authority interface | workspace configuration `authority/endpoint`, an `${endpoint:…}` reference the run resolves. Required | — (declared configuration) |
| Route enforcement | workspace configuration `hop/ENFORCEMENT`; `warn` makes the route check advisory, as the hop's is | — (declared configuration) |
| Each consumed module's hop and binding | the workspace configuration slots its `AuthorityRelay` names | — (declared configuration) |
| Mesh assertion | `codefly.For(ctx).WorkspaceValueIfSet("internal-transport", "mesh-protected")` — read once at boot and handed to the SDK's rule for a module's address; exactly `true` asserts that every in-cluster hop is carried by a mutually authenticated mesh, unset or `false` keeps plaintext refused, any other value is a refusal | — (declared configuration) |
| Projected workload credential | a **path**, re-read on every call to the authority; `/var/run/secrets/codefly/token`, the CLI projection | `CODEFLY__WORKLOAD_TOKEN_FILE` |
| Contract profile | the Codefly environment's own name, which is how Core resolves a profile for an environment that declares none | `CODEFLY__CONTRACT_PROFILE` |
| MF assets | `Manifest.Assets` when set (see below), else the `../fe-remote/dist` directory | `ASSETS_DIR` (directory only) |

**Removed with the saas host**: `GATEWAY_URL`, `CODEFLY_HOST_MODULE`,
`CODEFLY_HOST_GATEWAY`, `CODEFLY_HOST_FRONTEND`, `PUBLIC_URL`, the
`module-authority` group (`PRINCIPAL`, `AUDIENCE`, `PROJECTION_AUDIENCE`,
`INTERNAL_TOKEN`) and the `mcp` group (`issuer-url`, `public-url`). Setting any
of them now does nothing. The registration variables (`SELF_UPSTREAM`,
`HOST_REGISTER_URL` and the rest) and the `workload-identity` group went
earlier, with the registrations and the in-cell TLS they fed.

## Plain HTTP inside the cell

Past the authority's edge, every hop inside a cell is plain HTTP, and the
cell's mesh — istio ambient: ztunnel mTLS, the workload's identity being its
ServiceAccount's SPIFFE ID — carries transport security and destination
identity. TLS ends at the edge. So this listener is plain TCP on the port
Codefly resolved, presents no certificate and verifies no caller: a listener
that re-decided either would be a second copy of a decision the cell makes for
every workload. The previous generation served TLS 1.3 under a projected
X.509-SVID and admitted callers by provisioned peer files; all of it is
deleted.

What this process still decides is what a caller may do once admitted, and
where the viewer's Work Context may travel:

- **The authority's Check of the request's Work Context is the viewer.** No
  header a request wrote about itself is read.
- **A plaintext module address is admitted only where the mesh is.** Each
  relayed module's hop address is held to the SDK's one transport rule,
  `workcontext.AdmitEndpoint`: `https` to any host; `http` to a loopback host
  on a local run, or to an in-cluster Service address
  (`<svc>.<ns>.svc[.<domain>]`) when the composition asserts
  `internal-transport/mesh-protected=true`; anything else refuses the boot.
- **The listener bounds a stalled peer.** A request's headers must arrive
  within ten seconds and a keep-alive connection nobody uses is closed after
  thirty; neither bounds a whole request, because a declared long-running
  stream is conforming traffic.

## This runtime neither signs, parses nor verifies a capability

There is **one** implementation of a Work Context — Core's (`core/workcontext`:
deterministic proto, Ed25519) — and this runtime is not it. It has the
authority issue every Work Context it acts under, carries it as the string it travels as,
and lets whoever consumes it decide. It declares none of a capability's fields
and reads none of them: the capability a handler's gateway presents to a module
is a string this package never decoded, and the one check that must happen
before a call rather than at the far end — that a capability is sealed at all —
is the module's.

It also does not **verify**, and that is a position rather than an omission.
Core's verifier requires four live sources — the authorization revision,
replay, grants and seals — and refuses everything without them, deliberately,
so the strongest check in the model cannot become the easiest to skip. A
solution runtime holds none of those: it is the party presenting a capability,
not the party deciding on one. So there is no verifier here to configure, and a
change that adds one has to answer where those four sources come from.

Both halves are pinned by `work_context_boundary_test.go`, which fails on a
signing primitive, on a `WorkContext`-named type or function of this package's
own, and on a call to a verifier. The duplication it prevents already happened
once, in a module whose only job was to carry these things, and 3,532 lines had
to be deleted to get back to one implementation. Every step of that was locally
reasonable, which is why the first step fails a test here.

## The published contract

A solution **may declare** the most authority its passthrough may ever ask
for: which audiences it consumes, and the ceiling on each. A solution that
declares none publishes an empty contract and is bounded by the authority
alone — each call is issued through one of its bindings, within that binding's
ceiling and what the person holds. The runtime holds its own asks
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
checked against, so restating them would be a second source for one fact.

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
| no ceiling for a consumed audience | this runtime would have no declared ceiling to check the ask against, for a module it does call |
| a ceiling for an audience nothing consumes | the ceiling governs a call that cannot happen, and whoever wrote it believes otherwise |
| an ask outside its ceiling (action, or resource id) | the ceiling is what a reviewer approved; widening it is an edit, not an inference |
| an ask across a whole resource kind under a ceiling naming resources | "every document" is not inside "these two documents" |
| no profile at all, for a solution that declares a ceiling | a deployed process would have no profile to resolve its ceiling from |
| a profile name that is not a single path component | profile names select directories wherever one is read |

A running solution publishes the contract of the profile it runs under at
`/.well-known/module-contract` — the profile, and each binding with its ceiling
and the ask inside it. Nothing is pushed: answering
there makes this solution present to nobody. `ContractArtifact(id, contract,
modules...)` renders the same document at build time, with every profile,
checked by exactly the
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
- The **address the edge dials** is in the presence document's endpoints,
  resolved through the SDK from the carrier the CLI hands it, exactly as for a
  module. Nothing here reports it.

This solution still publishes what it is, at fixed paths, for anything that
asks: `/.well-known/solution.json` (the manifest: nav, the exposed module, the
federation manifest path, the backend's service alias, declared surfaces and an
optional dashboard, all from [the declared frontend](#the-declared-frontend)),
`/.well-known/capabilities` (the contract id and the majors),
`/.well-known/module-contract` (the authority contract above) and `/health`.
Publishing is not announcing — nothing is pushed, and answering makes this
solution present to nobody: the host builds its registry entry from the
delivered presence document and its own constants, never from this route.

`/health` reports process health and asks the authority nothing.

The manifest declares the majors it is built against rather than leaving a
reader to assume them — `schemaVersion: 1`, this runtime's manifest schema, and
`frontend.hostContract`, the host contract the author declared — and the
capability document declares the same majors from the same places, so a bump
cannot leave one document announcing the old major while the other announces
the new one.

### The declared frontend

A solution declares what the host lists it under in **one file**,
`solution.frontend.codefly.yaml`, beside the backend's `service.codefly.yaml`.
The backend embeds it — `//go:embed solution.frontend.codefly.yaml` into
`Manifest.Frontend` — and serves its manifest from it; the CLI reads the same
file into the presence document's `frontend` block (core's
`solutionhost.Frontend`), which is what the host's registry projects. Two
readers of one file cannot disagree, where a Go field beside a file could, and
nothing is reported at mint any more. The declaration is optional for either
component kind: a nil `Manifest.Frontend` is headless. A present malformed file
is refused by the same Core reader used by the CLI.

```yaml
title: Widgets           # nav title; one non-empty line
order: 10                # nav order; declared, zero included
exposed_module: ./Page   # the Module Federation module the host loads the page from
host_contract: 1         # the host page-contract major the page is built against; >= 1
dashboard:               # optional: a mapping the host's data-graph validator reads,
  events: [...]          # served and delivered as JSON, at most 64 KiB encoded
surfaces:                # optional: what the solution offers inside a client
  - id: footnote         # lowercase letters and digits, dashes between; unique per client
    client: word         # word, powerpoint, excel or slack
    title: Footnote
    description: Cite a claim.          # optional
    module: /surfaces/word/footnote.js  # a rooted path on this solution's own origin
    contract: 1                          # the surface contract major; >= 1
    applies: always                      # declared: "always", or {tagged: [one or more tags]}
    events: [documents.entry]            # optional; journal namespaces the surface reconciles on
```

The file is YAML, decoded strictly — an unknown key is refused by name — and
its top-level mapping is the block itself, with no wrapper and no schema key:
its keys are core's field names, field for field. Every scalar is declared,
because core refuses an omitted one rather than reading it as zero. The
dashboard is opaque to this runtime but has to be the JSON object the host
reads: a mapping, every key a string, no fraction (JSON spells those more than
one way, and the presence document is canonical bytes), bounded at 64 KiB
encoded. A surface declares its `applies` selector — `always`, or
`{tagged: [...]}` naming one or more tags — because core carries no default,
and names each of its `events` once, as a lowercase dotted journal namespace
(segments of letters and digits separated by a dot, dash or underscore). What
a tag selects and what a namespace names are the client's to interpret; the
shapes are what core signs.

`Manifest` keeps `ID`, `Contract` and `Capabilities` as Go fields: the id is
what the presence document names the solution by, and the capability handshake
at `/.well-known/capabilities` is the backend's own, which the frontend block
does not carry. `Title`, `Order`, `ExposedModule`, `Dashboard` and `Surfaces`
are gone from it with the `Surface` type; the MCP metadata document's
`resource_name` is the declared title.

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

### Letting the page call a consumed module: the passthrough

A page reaches only its own backend, through the authority's edge, and a module
authenticates every call by a Work Context addressed to it. Instead of a
handler per module operation, a solution declares which operations its page
may call, and where the composition says each module is:

```go
solution.New(manifest).Consumes(solution.ConsumedModule{
    As:     "documents", // the `as` of its api.consumes entry
    Scopes: []solution.Scope{{ResourceKind: "documents", Actions: []string{"read"}}},
    Methods: []solution.ConsumedMethod{{
        Name:     documentsv1.DocumentsService_GetDocument_FullMethodName,
        Response: solution.MustFieldMask(&documentsv1.GetDocumentResponse{}, "document.entry"),
    }},
    // Workspace configuration slots: the hop's gRPC address
    // (${endpoint:authority/hop/grpc}) and this solution's binding for the module.
    Authority: solution.AuthorityRelay{Group: "wiki", EndpointKey: "DOCUMENTS_ENDPOINT", BindingKey: "DOCUMENTS_BINDING"},
})
```

Each declared method is served as a Connect procedure at
`/v1/<id>/modules/<as>/<package.Service>/<Method>` — the edge routes a solution
at `/v1/<id>` and forwards requests unchanged — so the page uses the module's
own generated client (connect-es) unmodified, with the base URL
`<apiBase>/modules/<as>`. Each call is relayed over gRPC to the module's own
procedure, the face it serves behind the hop, as the viewer: a child of the
edge's Work Context issued by the authority through the module's binding
(`ForParent`) with the method's declared scopes, the pin merged in and only the
declared response fields returned. No `google.api.http` binding is read or
needed. The page names a procedure and a request message, never an address, a
binding or an authority, and authorization stays at the module, whose hop holds
each call to the module's own method policy.

**Why a relayed route is any checked caller's.** Every relayed route is
published in the interface artifact with `x-codefly-authority-policy:
{"any_checked_caller": true}`, and the runtime's `Check` names it as served
(`POST /v1/<id>/modules/<as>/<package.Service>/<Method>`), so an enforcing
authority admits it for what it declares rather than refusing it for declaring
nothing. The route row is not the gate, by design: the gate on a relayed call
is the per-call child the authority issues through the solution's declared
binding for the module — the person's current grants at the module (which
include what the solution's roles grant there) intersected with the binding's
invoke ceiling, narrowed to the method's declared scopes — and the module's
own method policy, which its hop applies to that child. A second route policy
of the solution's would restate, in the solution's vocabulary, what the binding
and the module's policy already decide, and could only disagree with them. The
child is issued per call (the passthrough builds a fresh gateway for each), and
each relayed call costs the authority three round trips: the `Check` of the
edge's context, the `Issue` of the child, and the hop's `Check` of the child.

**The authority is the only way a call reaches a module.** A solution that
declares consumed modules and has no `authority/endpoint` refuses to boot,
naming it; a module whose slots name no address or no binding refuses the boot
naming the slot; and an address the viewer's Work Context may not travel to (a
cleartext host off the machine that the mesh does not carry) is refused by the
SDK's endpoint rule. A solution that publishes no ceiling is bounded by the
authority.

Authority is asked per method. A method may declare its own `Scopes`, which
replace the module's for a call to that method — never add to them — so one
module's methods that need different authority are declared under one `as`:

```go
solution.ConsumedModule{
    As: "tasks",
    Methods: []solution.ConsumedMethod{
        {Name: ownListMethod, Scopes: []solution.Scope{{ResourceKind: "tasks", Actions: []string{"list"}}}, WholeResponse: true},
        {Name: orgListMethod, Scopes: []solution.Scope{{ResourceKind: "tasks", Actions: []string{"inspect"}}}, WholeResponse: true},
    },
    Authority: tasksRelay,
}
```

Each call asks only its own method's authority, and a viewer refused one
method is still served every other. Every method needs scopes, its own or the
module's.

Least privilege by default. A method that is not declared is `not_found`. At
boot, `Serve` refuses a module with no authority relay (or one naming fewer
than all three of its group, endpoint slot and binding slot), a method missing
from the registry, a client-streaming method, stream bounds on a unary method
or out of range, a method with no declared response fields, a method with no
scopes of its own or its module's, and a scope with no resource kind, no
action, or a blank or repeated action. `Response` names the fields returned to
the page; `WholeResponse` must be said explicitly. `Pin` fixes part of every
request server-side (merged with `proto.Merge`): a pinned scalar replaces the
page's value and a pinned repeated value is added to the page's, so a filter
clause the module ANDs stays in force whatever the page sends.

The authority's refusal reaches the page with the authority's code and reason.
A module's refusal of the page's own request (`invalid_argument`, `not_found`,
`permission_denied`, `failed_precondition`, …) keeps its code and message; any
other failure is reported by kind only and logged where an operator reads it,
since its text may name an internal address. `PassthroughOperations` renders
the declaration for the interface artifact (paths relative to the solution's
route), and `Server.InterfaceArtifact(dir, info)` renders a backend's whole
artifact from the server it serves — its operations, its MCP route, and the
passthrough at the paths they are served at, each with its policy — at the
version its `service.codefly.yaml` declares.

#### Streamed methods

A server-streaming method passes through too, as a Connect server-streaming
procedure at the same path, relayed as a gRPC stream to the module's own
procedure under the same authority as a unary call. The declared response
fields (`Response`, or `WholeResponse`) apply to **every** message of the
stream.

Every stream is bounded, and both bounds are declared per method:

| Field | Default | Refused at boot |
| --- | --- | --- |
| `MaxStreamDuration` | `DefaultStreamDuration` (5 min) | negative, or over `MaxStreamDurationLimit` (30 min) |
| `MaxStreamMessageBytes` | `DefaultStreamMessageLimit` (1 MiB) | negative |

A stream that reaches its duration ends with `deadline_exceeded`; a message
over its bound ends it with `resource_exhausted` and is never truncated; the
module ending its stream with a status ends the page's with that code. For a
streaming method `Timeout` bounds only the issue of the viewer's Work Context,
and `MaxResponseBytes` is refused (bound each message instead). The page
disconnecting cancels the module's stream at once.

In the interface artifact a streamed operation says so in its behaviour and
carries `x-streaming: server` (Swagger 2 has no stream; its 200 schema is one
message of it).

### Exposing an MCP server

A solution exposes its experience to an agent client the way it exposes it to
a browser: as the person the authority says the request is for, with the same
authority. The solution owns its tool surface; this runtime owns serving it:

```go
solution.New(solution.Manifest{ID: "notes", Frontend: frontend}).
    ServeMCP("notes", "v1.0.0", solution.Requires("notes.page", "read"), func(srv *mcp.Server) {
        mcp.AddTool(srv, &mcp.Tool{Name: "ask_notes", Description: "ask the notes a question"}, askNotes)
    }).
    Serve()
```

The endpoint is stateless Streamable HTTP (the official
`github.com/modelcontextprotocol/go-sdk`) at `/v1/<id>/mcp` (`MCPPath` under
the route the edge forwards). A tool call is admitted exactly as a handler
route is: the authority's `Check` of the Work Context the request carries,
naming the route `POST /v1/<id>/mcp`, so the solution's delivered route policy
applies to it. That policy is the one `ServeMCP` declares, and
`Server.InterfaceArtifact` publishes it for `POST /v1/<id>/mcp` like every
operation's, so the CLI derives the route's row from the same document and an
enforcing authority admits it. POST is the one method served; any other is
refused by name before the transport reads it. A request with no Work Context is answered 401 before the MCP
handler reads it; one the authority does not check runs no tool.
`ViewerFromContext(ctx)` returns the same viewer-bound `Gateway` a `Handler`
is given, so a tool reaches a module through `ForParent`:

```go
func askNotes(ctx context.Context, _ *mcp.CallToolRequest, in askIn) (*mcp.CallToolResult, askOut, error) {
    gw, err := solution.ViewerFromContext(ctx)
    if err != nil {
        return nil, askOut{}, err
    }
    notes, err := gw.ForParent(ctx, "notes-create", solution.Scope{ResourceKind: "conversations", Actions: []string{"create"}})
    ...
}
```

The viewer never comes from a tool's arguments, which a model writes. The
runtime's own errors are sanitized before a tool holds them, and an error
result naming an address this runtime dialled (the authority, a module's hop)
is replaced and logged. The endpoint carries no CORS: an MCP client is not a
browser page.

What is **not** here any more is the saas host's half: the OAuth 2.0
Protected Resource Metadata document, the `WWW-Authenticate` challenge, the
`mcp/issuer-url` and `mcp/public-url` values, and the gateway-stamped identity
the surface used to read. How an agent client obtains a Work Context for a
solution through the authority — robin calling a solution's tools, for the
person or as itself — is the authority's to answer; this transport serves
whatever context the edge sends.

### Generated messages in a response

A handler's value is encoded with `encoding/json`, which reads a generated
message's Go struct tags rather than producing protobuf JSON. Wrap an owner's
message in `solution.MessageOf(m)` (`solution.Message[T]`) wherever it sits in
the response, and it encodes as protobuf JSON. To pass on only part of an
owner's message, declare a `FieldMask` once from the paths allowed and
`solution.Apply` it. A field the owner adds later reaches nobody until it is
named, and a path naming no field fails at declaration.

### Documented operations

`Server.Operations` declares a list of `solution.Operation`s — each a method and
a route, its handler, its policy, and the documentation a reader needs
(summary, callers, behaviour, query parameters, request and response types).
It is the one way a backend serves a route of its own. `Server.InterfaceArtifact`
renders the same declaration as a Swagger 2.0 artifact (`InterfaceDocument`
renders any list), so one declaration is the source of what is served and what
is published, and an operation missing its documentation or its policy is
refused, at generation and at boot. A `Message[T]` field is described from its
descriptor, with protobuf JSON names.

The artifact's security scheme is the `x-codefly-work-context` header the edge
sends. Every operation also declares its `Policy`, what a call to the route must
hold: `solution.Requires(kind, actions...)` or `solution.AnyCheckedCaller()`,
the same shape as the authority's `authority.hop.v1.Policy`. The artifact
writes it as the operation's `x-codefly-authority-policy`, the extension the
CLI derives the solution's route rows from, and an operation that declares
none, or both, is refused at generation by name. The artifact has no base path
(`InterfaceInfo` has no `BasePath`): the edge forwards a solution's requests on
`/v1/<id>`, which its operations already carry, so each route is written as
served and is the `"<VERB> <template>"` the runtime's `Check` names. A path
ending in `/` serves its subtree and is written `/…/{path=**}`. The passthrough
routes `InterfaceArtifact` publishes beside the solution's own are any checked
caller's: see [why](#letting-the-page-call-a-consumed-module-the-passthrough).

**Every read is a Runnable operation, and so a tool.** Beside the policy of
each operation whose policy requires only `read`, `InterfaceArtifact` writes
core's `x-codefly-operation` marker — the proto3 JSON of
`codefly.runnable.v0.Operation` that core itself derives from that policy
(`runnable.RouteMarker`): recomputed on an uncertain outcome, core's default
bounds, invoked under exactly the scopes the policy requires, for the audience
this runtime's hop checks (`Manifest.ID`), presented as a read-only tool named
by `Operation.Tool` — or, left empty, by the operationId — and described by the
`Summary`.

`Operation.Tool` is the one part of the marker the owner says rather than core
derives, because it is the one part a model reads: snake_case, at most 64
characters, refused at validation rather than sanitised, since core's own
`toolName` keeps whatever it is given. One name names one operation, as an
operationId names one route — two reads claiming one name publish two tools a
model cannot tell apart, and nothing downstream collapses them. And only a read
is named, because only a read is marked: a name on a mutation, a stream, an
excluded route or an any-checked-caller route is a declaration that does
nothing and reads as the opposite, so it is refused. The fallback identifies the route and
describes nothing — `Wiki_Get_V1_Wiki_Upload-configuration` says where a route
is, not what calling it does. The operationId is deliberately not changed to
read better: generated clients are named from it, so moving it would rename
every caller's method to improve one tool's name. `codefly generate runnables`
then derives a Runnable package from it, as it does from every method a module
serves behind the hop; a `GET`'s query parameters are its input. A mutation is
not marked: it is resolved by an effect receipt, read through a receipt route
this runtime does not serve, so it stays a route its own page calls. Neither is
a route any checked caller may call, a stream, the MCP route or a relayed route.
`Operation.Exclude` keeps a read from every agent, as
`codefly.runnable.v0.exclude` keeps a module's method. Every object the artifact
defines closes `additionalProperties` — a struct marshals exactly its fields
and protojson refuses an undeclared one — which is what lets a Runnable
contract describe it.

> **Commit `Server.InterfaceArtifact`, never `InterfaceDocument`.**
> `InterfaceDocument` marks nothing — the marker names the audience the serving
> runtime's hop admits, which only the `Server` knows — so a solution that
> commits its output publishes no tool, silently, however many reads it serves.
> `InterfaceDocument` stays for documenting or validating a list of operations.
> `codefly generate runnables` names each read of a document that marks no route
> at all, which is this trap's signature (codefly-dev/cli#1185).

> **Dependency pins.** `go.mod` records the exact Core, SDK and authority
> client revisions used by this runtime, including unreleased commit
> pseudo-versions. No local `replace` directive is shipped. Core owns capability
> decoding and frontend validation; sdk-go owns resolution and endpoint
> admission; the authority client owns the authority's wire. Local source
> composition does not require publishing a release.
>
> **Open: the authority pins.** `codefly-dev/authority/libraries/authority-client/go`
> and `.../hop/go` are pinned at commits that are, today, only on the unmerged
> `authority/vision` branch of `codefly-dev/authority`. The module is private
> and fetched direct, so a squash merge and a branch deletion would orphan both
> commits. This closes when authority#1 merges **with a merge commit** (which
> keeps both commits reachable from `main`) and this runtime re-pins to that
> merge or a tag; no runtime release is cut before then.
### Shared frontend validation and headless components

`Manifest.Frontend == nil` declares a headless component: it boots normally and
its frontend manifest route returns 404. A present file, including an empty one,
is validated by Core's `solutionhost.ParseFrontend`, the same reader the CLI uses
for modules and solutions before signed delivery. The runtime carries Core's
frontend types and bounds directly; it no longer maintains a client-kind list
or a second set of field validators. Client kinds are declared names, with
support decided by the consuming client.

Core limits text to 1 KiB, surface/event/tag collections to 64 entries, a
dashboard to 64 KiB and the complete canonical frontend to 128 KiB. These are
file/declaration constraints, independent of per-organisation page admission.
