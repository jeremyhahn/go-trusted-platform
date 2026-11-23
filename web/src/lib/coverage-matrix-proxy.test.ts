// @vitest-environment node
import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

// #2061: every ProxyService operation is covered by the proxy routes or pools
// page and the real-server Playwright spec that visits it.

const matrixPath = path.resolve(process.cwd(), "..", "docs", "ui", "coverage-matrix.md");

const routesPage = "`(dashboard)/networking/proxy/page.tsx`";
const poolsPage = "`(dashboard)/networking/proxy/pools/page.tsx`";
const routesSpec = "`real-server/proxy-routes.spec.ts`";
const poolsSpec = "`real-server/proxy-pools.spec.ts`";

function row(op: string, rest: string, page: string, spec: string): string {
  return `| \`ProxyService.${op}\` | \`${rest}\` | ${page} | - | ${spec} | covered |`;
}

const expected = [
  row("CreateRoute", "POST /routes", routesPage, routesSpec),
  row("GetRoute", "GET /routes/{id}", routesPage, routesSpec),
  row("UpdateRoute", "PUT /routes/{id}", routesPage, routesSpec),
  row("DeleteRoute", "DELETE /routes/{id}", routesPage, routesSpec),
  row("ListRoutes", "GET /routes", routesPage, routesSpec),
  row("CreatePool", "POST /pools", poolsPage, poolsSpec),
  row("GetPool", "GET /pools/{id}", poolsPage, poolsSpec),
  row("UpdatePool", "PUT /pools/{id}", poolsPage, poolsSpec),
  row("DeletePool", "DELETE /pools/{id}", poolsPage, poolsSpec),
  row("ListPools", "GET /pools", poolsPage, poolsSpec),
  row("GetProxyConfig", "GET /config", poolsPage, poolsSpec),
  row("GetProxyStatus", "GET /status", routesPage, routesSpec),
  row("ReloadProxyConfig", "POST /reload", routesPage, routesSpec),
  row("GetZoneMatrix", "GET /zone-matrix", poolsPage, poolsSpec),
  "| ProxyService | 14 | 14 | 0 | 0 | 0 | 0 |",
];

describe("coverage matrix: ProxyService", () => {
  it("lists each ProxyService operation as covered by its proxy page and real-server spec", () => {
    const lines = fs.readFileSync(matrixPath, "utf8").split("\n");

    for (const want of expected) {
      expect(lines.filter((l) => l === want), want).toHaveLength(1);
    }
    const missing = lines.filter(
      (l) => l.startsWith("| `ProxyService.") && l.endsWith("| missing |")
    );
    expect(missing).toEqual([]);
  });

  it("names files that exist", () => {
    for (const file of [
      "src/app/(dashboard)/networking/proxy/page.tsx",
      "src/app/(dashboard)/networking/proxy/pools/page.tsx",
      "e2e/real-server/proxy-routes.spec.ts",
      "e2e/real-server/proxy-pools.spec.ts",
    ]) {
      expect(fs.existsSync(path.resolve(process.cwd(), file)), file).toBe(true);
    }
  });
});
