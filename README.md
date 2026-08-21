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
