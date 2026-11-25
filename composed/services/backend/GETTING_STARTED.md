# The codefly-base solution's backend

Scaffolded by `codefly.dev/solution-go`. Two directories were written:

- `services/backend` — this service, the solution's entry service.
- `services/fe-remote` — the `./Page` Module Federation remote. An npm package,
  not a Codefly service, which is why nothing else writes it.

## What is left, in order

1. `cd services/backend && go build ./... && go test ./...`
2. `cd services/fe-remote && npm install && npm test && npm run typecheck`
   The `@codefly-dev/*` kits come from GitHub Packages, so `NODE_AUTH_TOKEN`
   must be set to a token with `read:packages` (see `.npmrc`).
3. Declare what the page may read, under `api.consumes` in the solution's
   `solution.codefly.yaml`, then `codefly sync` to regenerate `consumed_gen.go`
   and fill in that module's entry in `consumes.go`.
   Add a binding to `module.contract.codefly.yaml` for each one, and have the
   composition fill its two slots — `<AS>_ENDPOINT` and `<AS>_BINDING` in this
   solution's own configuration group. The runtime opens a relay for every
   declared module at boot and refuses the boot while a slot is empty.
4. Serve a route of your own: add a `solution.Operation` in `operations.go`,
   then `go generate ./...` to re-render `openapi/api.swagger.json`. That
   document is what `codefly generate contracts` publishes as this endpoint's
   contract, and the CLI derives the rows the authority's Check applies from it.
5. Read a configuration value with `github.com/codefly-dev/sdk-go`
   (`codefly.For(ctx).WorkspaceConfiguration(group, key)`) and add it to
   `go.mod` when you do. Nothing is scaffolded that reads one.

## If this service was added with `codefly add service` rather than `codefly add solution`

`codefly add solution` writes the five declarations a solution is installed
from and the shape of this service's manifest. Added on its own, this service
has none of them, and it needs all of this in `service.codefly.yaml`:

```yaml
module-identity: true
service-dependencies:
  - interface: codefly.dev/authority@>=0.2.0 <0.4.0
  - name: hop
    module: authority
    kind: external
    endpoints:
      - name: grpc
workspace-configuration-dependencies:
  - authority
  - codefly-base
endpoints:
  - name: http
    visibility: public
    exposure: none
    api: http
    secured: false
    health:
      readiness:
        kind: http
        path: /health
        statuses: ["200"]
```

Never add a `service-dependencies` entry for a module this solution consumes.
Every module is reached through `authority/hop`, which checks the call; a
direct edge renders into a mesh allow rule past that check.

It also needs `solution.frontend.codefly.yaml` beside this file, which
`main.go` embeds, and the solution's own `solution.codefly.yaml`,
`module.contract.codefly.yaml` and `module.package.codefly.yaml` one directory
above `services/`. `codefly add solution <name> --package-id <owner>/<name>
--agent solution-go` writes all of them.
