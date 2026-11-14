import { describe, expect, it } from "vitest";

import { cn } from "./utils";

// #1795: cn joins class names the way clsx does and lets the later of two
// conflicting Tailwind classes win, so a caller's className overrides a
// component's default.

describe("cn", () => {
  it("joins class names", () => {
    expect(cn("px-2", "py-1")).toBe("px-2 py-1");
  });

  it("returns an empty string for no input", () => {
    expect(cn()).toBe("");
    expect(cn("")).toBe("");
  });

  it("drops falsy inputs", () => {
    expect(cn("a", undefined, null, false, 0, "", "b")).toBe("a b");
  });

  it("reads arrays and conditional objects", () => {
    expect(cn(["a", ["b", { c: true, d: false }]], { e: 1, f: 0 })).toBe("a b c e");
  });

  it("lets the later conflicting Tailwind class win", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
    expect(cn("text-red-500", "text-blue-500")).toBe("text-blue-500");
    expect(cn("p-4", "px-2")).toBe("p-4 px-2");
  });

  it("keeps classes that do not conflict", () => {
    expect(cn("text-sm", "text-red-500")).toBe("text-sm text-red-500");
    expect(cn("hover:bg-red-500", "bg-blue-500")).toBe("hover:bg-red-500 bg-blue-500");
  });

  it("collapses surplus whitespace", () => {
    expect(cn("  a   b ", " c")).toBe("a b c");
  });
});
