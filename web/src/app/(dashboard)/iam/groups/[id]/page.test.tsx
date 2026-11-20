import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

afterEach(() => cleanup());

vi.mock("./group-detail-client", () => ({
  default: () => <div data-testid="group-detail-client" />,
}));

import Page, { generateStaticParams } from "./page";

describe("iam/groups/[id] page", () => {
  it("generateStaticParams returns exactly the placeholder id", () => {
    const params = generateStaticParams();
    expect(params).toHaveLength(1);
    expect(Object.keys(params[0])).toEqual(["id"]);
    expect(typeof params[0].id).toBe("string");
    expect(params[0].id.length).toBeGreaterThan(0);
  });

  it("generateStaticParams returns a fresh array on each call", () => {
    const a = generateStaticParams();
    expect(a).not.toBe(generateStaticParams());
    expect(a).toEqual(generateStaticParams());
  });

  it("Page renders the group detail client", () => {
    render(<Page />);
    expect(screen.getByTestId("group-detail-client")).toBeTruthy();
  });
});
