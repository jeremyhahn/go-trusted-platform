import path from "path";
import { defineConfig } from "vitest/config";

// Unit tests for hooks, stores and contexts. Playwright (`npm test`) owns the
// browser flows; this runner owns the pieces that can be exercised in jsdom
// without a server. Mirrors sdk/javascript/vitest.config.ts.
const webStorageFlag = "--no-experimental-webstorage";
const webStorageExecArgv = process.allowedNodeEnvironmentFlags.has(webStorageFlag)
  ? [webStorageFlag]
  : [];

export default defineConfig({
  test: {
    environment: "jsdom",
    // https origin: the session cookie is written with `secure: true`, and
    // jsdom drops Secure cookies on an http origin, which would make login()
    // look like a no-op in tests.
    environmentOptions: { jsdom: { url: "https://localhost/" } },
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    exclude: ["node_modules", ".next", "out", "e2e"],
    testTimeout: 10000,
    // Node 26's built-in localStorage global is undefined without
    // --localstorage-file and shadows jsdom's window.localStorage (#1871).
    // The flag is gated: Node 20 does not know it and refuses to start the
    // worker, so it is passed only where the running Node accepts it.
    poolOptions: {
      forks: { execArgv: webStorageExecArgv },
      threads: { execArgv: webStorageExecArgv },
    },
    // The SDK is linked from ../sdk/javascript, which has its own dev copy of
    // react. Externalized, its hooks would import that second React and fail
    // with "Invalid hook call". Inlining runs it through Vite, where `dedupe`
    // below resolves react to this package's copy — the test-side equivalent
    // of next.config's transpilePackages.
    server: { deps: { inline: ["trusted-platform-sdk"] } },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
    dedupe: ["react", "react-dom"],
  },
});
