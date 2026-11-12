import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// #1827: the VM detail route is a static-export shell. generateStaticParams
// emits the one placeholder id the export needs, and the page renders the
// client component, which reads the real id at runtime.

vi.mock("./vm-detail-client", () => ({
  default: () => <div data-testid="vm-detail-client" />,
}));

describe("VM detail route", () => {
  afterEach(() => {
    cleanup();
  });

  it("emits exactly one placeholder param for the static export", () => {
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });

  it("returns a fresh array on every call", () => {
    const first = generateStaticParams();
    first.push({ id: "mutated" });
    expect(generateStaticParams()).toHaveLength(1);
  });

  it("renders the client component and nothing else", () => {
    const { container } = render(<Page />);
    expect(screen.getByTestId("vm-detail-client")).toBeTruthy();
    expect(container.childElementCount).toBe(1);
  });
});
