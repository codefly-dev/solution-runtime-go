# solution-runtime-go

Generic Go runtime for **codefly solutions** — independently deployed modules
that plug into a host at runtime with no build-time coupling. Owns registration
(host + gateway, with heartbeat), CORS, Module Federation asset serving, the
capability handshake, the manifest, and a bearer-forwarding gateway client.

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
| Gateway URL (auth-sidecar `rest`) | `Endpoint("rest").Module(...).Service(...)` | `GATEWAY_URL` |
| Host frontend URL | `Endpoint("http").Module(...).Service(...)` | — (feeds the host register URL) |
| Host register URL | `<frontend>/api/solutions/register` | `HOST_REGISTER_URL` |
| Gateway register URL | `<gateway>/solutions/_register` | `GATEWAY_REGISTER_URL` |
| Internal-auth token | `codefly.For(ctx).WorkspaceSecret("internal-auth", "CODEFLY_INTERNAL_TOKEN")` — the namespaced secret Codefly injects | `CODEFLY_INTERNAL_TOKEN` |
| Self upstream | `<public-url>` | `SELF_UPSTREAM` |
| MF assets dir | `../fe-remote/dist` | `ASSETS_DIR` |

The host it plugs into is named by Codefly-convention roles, themselves
overridable: `CODEFLY_HOST_MODULE` (default `saas-starter`),
`CODEFLY_HOST_FRONTEND` (default `frontend`), `CODEFLY_HOST_GATEWAY` (default
`auth-sidecar`); their concrete addresses come from the SDK.

On boot the runtime self-registers on a 15s heartbeat with **both** the host
frontend (host registration) and the gateway (gateway registration), sending the
internal token as the `x-codefly-internal-token` header on every beat.

> **Note:** SDK in-process endpoint resolution for a solution composed on an
> out-of-repo host currently depends on codefly-core accepting the composed
> module path in its workspace loader (tracked in codefly-dev/core#365). Until
> that ships it is wired via a `go.mod` `replace`.
