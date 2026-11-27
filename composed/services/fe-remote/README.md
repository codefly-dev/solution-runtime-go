# Codefly Base — the `./Page` remote

The Module Federation remote a saas host federates, and the page the solution's
own shell (`../web`) serves where no host shell mounts it. Both read one build.

It is an **npm package, not a Codefly service**: no `codefly add service` call
reaches it, which is why the `solution-go` agent writes it from the backend's
own Create.

```sh
npm install          # NODE_AUTH_TOKEN needs read:packages — see .npmrc
npm test
npm run typecheck
npm run build        # the backend serves the output at /assets/
```

- `src/binding.ts` is the host↔remote contract, picked from
  `@codefly-dev/saas-ui/solution`'s `SolutionBinding`. Never restate a field
  there and never require one an older host may not inject.
- `rsbuild.config.ts` carries the shared-singleton policy. Every entry in it
  must be the host's single instance; read the comments before changing one.
- The title and nav order the host's shell shows come from the backend's
  `solution.frontend.codefly.yaml`, not from this package.
