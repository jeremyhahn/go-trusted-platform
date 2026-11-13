import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// #1844: the route wrapper only names the static-export placeholder and
// renders the client component; the client component is tested on its own.
vi.mock("./dns-zone-detail-client", () => ({
  default: () => <div data-testid="dns-zone-detail-client" />,
}));

import Page, { generateStaticParams } from "./page";

afterEach(() => {
  cleanup();
});

describe("generateStaticParams", () => {
  it("returns the single placeholder zone the static export needs", () => {
    expect(generateStaticParams()).toEqual([{ zone: "__placeholder__" }]);
  });

  it("returns a fresh array on each call", () => {
    const first = generateStaticParams();
    first.push({ zone: "mutated" });
    expect(generateStaticParams()).toEqual([{ zone: "__placeholder__" }]);
  });
});

describe("Page", () => {
  it("renders the DNS zone detail client component", () => {
    render(<Page />);
    expect(screen.getByTestId("dns-zone-detail-client")).toBeTruthy();
  });

  it("renders the client component exactly once", () => {
    render(<Page />);
    expect(screen.getAllByTestId("dns-zone-detail-client")).toHaveLength(1);
  });
});
