import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// The route page is a thin server wrapper: it hands its params promise to the
// client component untouched. The client is mocked so the test sees exactly
// what the wrapper passes on.
const received: Array<Promise<{ id: string }>> = [];

vi.mock("./attestation-detail-client", () => ({
  default: ({ params }: { params: Promise<{ id: string }> }) => {
    received.push(params);
    return <div data-testid="attestation-detail-client">client</div>;
  },
}));

describe("attestation [id] generateStaticParams", () => {
  it("returns the single placeholder id the static export needs", () => {
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });

  it("returns a fresh array on every call", () => {
    const first = generateStaticParams();
    first.push({ id: "other" });
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });
});

describe("attestation [id] Page", () => {
  afterEach(() => {
    cleanup();
    received.length = 0;
  });

  it("renders the detail client with the same params promise", async () => {
    const params = Promise.resolve({ id: "m-1" });
    render(<Page params={params} />);

    expect(screen.getByTestId("attestation-detail-client")).toBeTruthy();
    expect(received).toHaveLength(1);
    expect(received[0]).toBe(params);
    await expect(received[0]).resolves.toEqual({ id: "m-1" });
  });

  it("passes an empty id through without rewriting it", async () => {
    const params = Promise.resolve({ id: "" });
    render(<Page params={params} />);

    expect(received[0]).toBe(params);
    await expect(received[0]).resolves.toEqual({ id: "" });
  });

  it("passes a rejected params promise through for the client to handle", async () => {
    const params = Promise.reject(new Error("no route params"));
    params.catch(() => undefined);
    render(<Page params={params} />);

    expect(received[0]).toBe(params);
    await expect(received[0]).rejects.toThrow("no route params");
  });
});
