import path from "path";
import { defineConfig } from "vitest/config";

// Unit tests for hooks, stores and contexts. Playwright (`npm test`) owns the
// browser flows; this runner owns the pieces that can be exercised in jsdom
// without a server. Mirrors sdk/javascript/vitest.config.ts.
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
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
