import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// The client component is tested on its own; the route only mounts it.
const clientRender = vi.fn();
vi.mock("./user-detail-client", () => ({
  default: (props: Record<string, unknown>) => {
    clientRender(props);
    return <div data-testid="user-detail-client" />;
  },
}));

afterEach(() => {
  cleanup();
  clientRender.mockClear();
});

describe("generateStaticParams", () => {
  it("exports one placeholder id for the static export", () => {
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });

  it("returns a fresh list on each call", () => {
    const first = generateStaticParams();
    first.push({ id: "mutated" });
    expect(generateStaticParams()).toEqual([{ id: "__placeholder__" }]);
  });
});

describe("Page", () => {
  it("renders the user detail client component once, without props", () => {
    render(<Page />);
    expect(screen.getByTestId("user-detail-client")).toBeTruthy();
    expect(clientRender).toHaveBeenCalledTimes(1);
    expect(clientRender).toHaveBeenCalledWith({});
  });
});
