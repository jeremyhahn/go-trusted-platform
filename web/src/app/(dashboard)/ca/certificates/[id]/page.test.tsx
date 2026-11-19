import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// Page is a thin server wrapper: it hands its params promise to the client
// component unchanged. The client is stubbed so the test sees what it gets.
const received: Array<Promise<{ id: string }>> = [];

vi.mock("./cert-detail-client", () => ({
  default: ({ params }: { params: Promise<{ id: string }> }) => {
    received.push(params);
    return <div data-testid="cert-detail-client" />;
  },
}));

describe("generateStaticParams", () => {
  it("returns the single placeholder id the static export needs", () => {
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

describe("certificate detail Page", () => {
  afterEach(() => {
    cleanup();
    received.length = 0;
  });

  it("renders the client component with the same params promise", async () => {
    const params = Promise.resolve({ id: "0A1B2C" });
    render(<Page params={params} />);
    expect(screen.getByTestId("cert-detail-client")).toBeTruthy();
    expect(received[0]).toBe(params);
    await expect(received[0]).resolves.toEqual({ id: "0A1B2C" });
  });

  it("passes a rejecting params promise through without awaiting it", async () => {
    const params = Promise.reject(new Error("bad route"));
    params.catch(() => {});
    render(<Page params={params} />);
    expect(received[0]).toBe(params);
    await expect(received[0]).rejects.toThrow("bad route");
  });
});
