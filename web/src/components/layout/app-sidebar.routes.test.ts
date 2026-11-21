import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The web is a static export (output: export): a link whose page.tsx is
// absent lands on the root fallback. Every route the sidebar and the
// container table link to must have a page on this branch.

// Vitest runs from web/ (the jsdom environment gives import.meta.url an
// http scheme, so the path is taken from the working directory).
const SRC = join(process.cwd(), "src");
const APP = join(SRC, "app");

// Dynamic segments export only the `__placeholder__` value (each page's
// generateStaticParams), so a link may reach a [param] page only through
// that value or a runtime value (a template literal).
const PLACEHOLDER = "__placeholder__";
const RUNTIME = "${}";

function pageRoutes(dir: string, prefix: string[] = []): string[][] {
  const routes: string[][] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      // Route groups such as (dashboard) do not appear in the URL.
      const next = /^\(.*\)$/.test(entry) ? prefix : [...prefix, entry];
      routes.push(...pageRoutes(full, next));
    } else if (entry === "page.tsx") {
      routes.push(prefix);
    }
  }
  return routes;
}

const routes = pageRoutes(APP);

function hasPage(href: string): boolean {
  const segments = href.split("/").filter(Boolean);
  return routes.some(
    (route) =>
      route.length === segments.length &&
      route.every((part, i) => {
        if (/^\[.+\]$/.test(part)) return segments[i] === PLACEHOLDER || segments[i] === RUNTIME;
        return part === segments[i];
      }),
  );
}

// href: "/x", href="/x" and href={`/x/${id}`}; a ${...} part becomes "${}".
function linkedHrefs(file: string): string[] {
  const text = readFileSync(join(SRC, file), "utf8");
  const hrefs: string[] = [];
  for (const m of text.matchAll(/href(?::\s*|=)"(\/[^"]*)"/g)) hrefs.push(m[1]);
  for (const m of text.matchAll(/href=\{`(\/[^`]*)`\}/g)) hrefs.push(m[1].replace(/\$\{[^}]*\}/g, RUNTIME));
  return hrefs;
}

describe("links to pages", () => {
  it("finds the app's pages", () => {
    expect(hasPage("/dashboard")).toBe(true);
    expect(hasPage("/tpm/vtpm/__placeholder__")).toBe(true);
    expect(hasPage("/no/such/page")).toBe(false);
    expect(linkedHrefs("components/layout/app-sidebar.tsx")).toContain("/dashboard");
  });

  it.each(["components/layout/app-sidebar.tsx", "components/features/compute/container-table.tsx"])(
    "%s links only to routes with a page",
    (file) => {
      const hrefs = linkedHrefs(file);
      expect(hrefs.filter((href) => !hasPage(href))).toEqual([]);
    },
  );

  // #2145 Codex round 1: the pages later splits add are not linked until they land.
  it.each([
    "/iam/policies/test", "/tenant/lifecycle", "/kms/operations", "/ca/eab", "/ca/sign", "/ca/verify",
    "/attestation/collect", "/tpm/idevid", "/devices/bmc", "/devices/lookup", "/compute/migrations",
    "/networking/switches", "/networking/gateway/bgp",
  ])("defers %s until its page is on this branch", (href) => {
    expect(hasPage(href)).toBe(false);
    expect(linkedHrefs("components/layout/app-sidebar.tsx")).not.toContain(href);
  });
});
