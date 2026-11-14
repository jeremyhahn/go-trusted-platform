import { describe, expect, it, vi } from "vitest";
import { isValidElement, type ReactElement } from "react";

vi.mock("./key-detail-client", () => ({
  default: function KeyDetailClientStub() {
    return null;
  },
}));

import Page, { generateStaticParams } from "./page";
import KeyDetailClient from "./key-detail-client";

describe("kms/[id] generateStaticParams", () => {
  it("returns exactly one placeholder id for the static export", () => {
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });

  it("returns a fresh array on every call", () => {
    const a = generateStaticParams();
    const b = generateStaticParams();
    expect(a).not.toBe(b);
    a.push({ id: "mutated" });
    expect(generateStaticParams()).toHaveLength(1);
  });
});

describe("kms/[id] Page", () => {
  it("renders the key detail client with the same params promise", () => {
    const params = Promise.resolve({ id: "key-1" });
    const el = Page({ params }) as ReactElement<{ params: Promise<{ id: string }> }>;
    expect(isValidElement(el)).toBe(true);
    expect(el.type).toBe(KeyDetailClient);
    expect(el.props.params).toBe(params);
  });

  it("passes an empty id through unchanged", async () => {
    const params = Promise.resolve({ id: "" });
    const el = Page({ params }) as ReactElement<{ params: Promise<{ id: string }> }>;
    await expect(el.props.params).resolves.toEqual({ id: "" });
  });

  it("passes a rejecting params promise through without awaiting it", async () => {
    const params = Promise.reject(new Error("bad params"));
    const el = Page({ params }) as ReactElement<{ params: Promise<{ id: string }> }>;
    expect(el.props.params).toBe(params);
    await expect(el.props.params).rejects.toThrow("bad params");
  });
});
