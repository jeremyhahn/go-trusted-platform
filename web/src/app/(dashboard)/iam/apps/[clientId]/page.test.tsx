import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

afterEach(() => cleanup());

vi.mock("./app-detail-client", () => ({
  default: () => <div data-testid="app-detail-client" />,
}));

import Page, { generateStaticParams } from "./page";

describe("iam/apps/[clientId] page", () => {
  it("generateStaticParams returns exactly the placeholder client id", () => {
    const params = generateStaticParams();
    expect(params).toEqual([{ clientId: "__placeholder__" }]);
    expect(params).toHaveLength(1);
  });

  it("generateStaticParams returns a fresh array on each call", () => {
    const a = generateStaticParams();
    const b = generateStaticParams();
    expect(a).not.toBe(b);
    a.push({ clientId: "mutated" });
    expect(generateStaticParams()).toHaveLength(1);
  });

  it("Page renders the app detail client", () => {
    render(<Page />);
    expect(screen.getByTestId("app-detail-client")).toBeTruthy();
  });
});
