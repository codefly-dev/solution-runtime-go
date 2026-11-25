import { pluginModuleFederation } from "@module-federation/rsbuild-plugin";
import { defineConfig } from "@rsbuild/core";
import { pluginReact } from "@rsbuild/plugin-react";

// The backend serves this static remote at /assets/, and a saas host federates
// the same `./Page` directly. Both read one build.
//
// `name` is emitted by Module Federation as a JavaScript GLOBAL, so it must be
// an identifier: "codefly-base" yields "codefly_base". The
// solution-go agent refuses a module name that cannot become one, so a bundler
// never has to.
const name = "codefly_base";

// EVERY ENTRY HERE MUST BE THE HOST'S SINGLE INSTANCE, or its React context
// and its skin tokens do not line up across the federation boundary and the
// kit renders unstyled, stale, or not at all. These are not performance
// settings.
const hostSingleton = { singleton: true, requiredVersion: false } as const;

// `import: false` means "never bundle a copy": the host always provides these,
// and a second copy of a plugin entrypoint is a second React context.
const hostProvided = { ...hostSingleton, import: false } as const;

// A share key is an EXACT module specifier, so every key here is spelled as
// one — quoted, even where JavaScript would accept a bare identifier. A bare
// `react` and a quoted "react" mean the same thing to a bundler and two
// different things to a reader skimming for a missing entry.
const shared = {
  "react": { ...hostSingleton },
  "react/jsx-runtime": { ...hostSingleton },
  "react-dom": { ...hostSingleton },
  // A share key is an EXACT specifier. A kit that mounts its own root with
  // createRoot from react-dom/client gets its own react-dom build unless this
  // exact key is shared, and that build refuses the host's React (React error
  // #527) — the whole page then fails to load.
  "react-dom/client": { ...hostSingleton },
  "@codefly-dev/ui": { ...hostSingleton },
  "@codefly-dev/saas-ui": { ...hostSingleton },
  "@codefly-dev/saas-sdk": { ...hostSingleton },
  // Each plugin entrypoint must have one identity in a direct import and in
  // the UI wrappers alike.
  "@codefly-dev/saas-plugin-contract": { ...hostProvided },
  "@codefly-dev/saas-plugin-contract/capabilities": { ...hostProvided },
  "@codefly-dev/saas-plugin-react": { ...hostProvided },
  "@codefly-dev/saas-plugin-react/runtime": { ...hostProvided },
  "@codefly-dev/saas-plugin-react/ui": { ...hostProvided },
};

// "auto" makes the container resolve its chunk URLs at runtime, relative to
// wherever its remoteEntry was loaded from, so one build is servable from any
// backend origin with none baked in.
const assetPrefix = process.env.ASSET_PREFIX ?? "auto";

// PORT is the dev server's; nothing deployed reads it, and the backend's own
// port is Codefly-assigned.
const port = Number(process.env.PORT ?? 3100);

export default defineConfig({
  plugins: [pluginReact(), pluginModuleFederation({ name, exposes: { "./Page": "./src/Page.tsx" }, dts: false, shared })],
  // The host is a different origin and fetches the remote entry and its chunks.
  server: { port, cors: true },
  dev: { assetPrefix },
  output: {
    assetPrefix,
    // Inline this remote's CSS into its JS. A host's CSP allows
    // `style-src 'self' 'unsafe-inline'` and does not widen for a solution
    // origin, so a cross-origin <link rel=stylesheet> is refused and the page
    // fails to mount ("Loading CSS chunk … failed"). Injected styles are
    // covered by 'unsafe-inline'.
    injectStyles: true,
  },
});
