import type { NextConfig } from "next";
import { resolve } from "node:path";

const config: NextConfig = {
  // The remote lives beside this app, not under it.
  experimental: { externalDir: true },
  // It ships its SOURCE, as the host's remote build reads it, so the shell
  // compiles it rather than consuming a build.
  transpilePackages: ["codefly-base-fe-remote"],
  turbopack: {
    // THE BUILD ROOT IS THE SOLUTION'S, not this app's. The remote is linked
    // into node_modules as a symlink to ../../fe-remote, and Turbopack
    // refuses to follow a symlink out of its root: "Symlink
    // node_modules/codefly-base-fe-remote/src/Page.tsx could not be resolved: the symlink target
    // leaves the configured filesystem roots", served as a 500 while the
    // link, the package's exports map and the file are all correct.
    root: resolve("../../.."),
    resolveExtensions: [".tsx", ".ts", ".jsx", ".js", ".mjs", ".json"],
  },
};

export default config;
