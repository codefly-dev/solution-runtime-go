import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    // @codefly-dev/saas-sdk's published dist imports its generated modules
    // without file extensions, which a bundler resolves and Node's ESM loader
    // does not. Letting Vite transform it — and saas-ui, which imports it — is
    // how a test loads it at all.
    server: { deps: { inline: ["@codefly-dev/saas-sdk", "@codefly-dev/saas-ui"] } },
  },
});
