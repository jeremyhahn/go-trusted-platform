import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

// #1747 Codex round 3 (P1): the PR delivers only part of #1732, so the plan
// must revise the slice's scope explicitly and keep the deferred operations
// tracked as remaining #1732 work, with #1732 left open by this PR.
const plan = readFileSync(
  resolve(process.cwd(), "..", "docs", "plans", "1732.md"),
  "utf8",
);

function section(heading: string): string {
  const start = plan.indexOf(`\n## ${heading}\n`);
  if (start < 0) return "";
  const rest = plan.slice(start + heading.length + 5);
  const end = rest.indexOf("\n## ");
  return end < 0 ? rest : rest.slice(0, end);
}

describe("docs/plans/1732.md scope (#1747 Codex round 3)", () => {
  it("revises the slice scope to the operations this PR delivers", () => {
    const revision = section("Scope revision (#1747)");
    expect(revision).not.toBe("");
    expect(revision).toContain("DeleteManifest");
    expect(revision).toContain("CollectHostAttestation");
    expect(revision).toMatch(/Refs #1732/);
    expect(revision).not.toMatch(/Closes #1732/);
  });

  it("keeps each deferred operation tracked with its prerequisite", () => {
    const remaining = section("Remaining in #1732 (issue stays open)");
    expect(remaining).not.toBe("");
    for (const op of [
      "VerifyManifest",
      "CollectVMAttestation",
      "CollectContainerAttestation",
    ]) {
      const line = remaining.split("\n").find((l) => l.includes(op));
      expect(line, `${op} tracked`).toBeDefined();
      expect(line, `${op} prerequisite`).toMatch(/prerequisite/i);
    }
  });
});
