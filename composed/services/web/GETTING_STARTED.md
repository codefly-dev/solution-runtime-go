# Getting Started

## Development

```bash
cd code
npm ci
npm run dev
```

Your app will be running at http://localhost:3000.

`npm ci` installs exactly what `package-lock.json` records, which is what CI and
the production container build install too. The framework version comes from
this application, not from the agent release: `package.json` declares it and the
lockfile pins it. Commit both whenever either changes.

## Testing

```bash
npm test
```

## Structure

```
code/
├── src/
│   ├── app/           # App Router pages and layouts
│   ├── lib/           # Shared utilities, hooks, transforms
│   ├── stores/        # Zustand stores
│   └── test/          # Test setup and MSW mocks
├── packages/          # Additive application-owned npm workspaces
├── next.config.ts
├── tsconfig.json
└── package.json
```

## Application packages

The generated application supports npm workspaces below `code/packages/*`.
Packages are application-owned and must be imported through an explicit
composition root. The generic Next.js agent intentionally provides no package
scanner, self-registration mechanism, product contract, or deployment URL.

When adding a package, declare its exact dependency in `code/package.json`,
regenerate `code/package-lock.json`, and run lint, typecheck, tests, and a
production build. SaaS applications should consume the public SDK owned by the
SaaS Starter instead of creating a second contract in this template.
