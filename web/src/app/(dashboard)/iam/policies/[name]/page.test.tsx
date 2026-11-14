import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// The route wrapper only hands off to the client component, which has its
// own tests: stand it in with a marker.
vi.mock("./policy-detail-client", () => ({
  default: () => <div data-testid="policy-detail-client" />,
}));

afterEach(cleanup);

describe("policies/[name] route", () => {
  it("exports a single placeholder static param for the export build", () => {
    const params = generateStaticParams();
    expect(params).toEqual([{ name: "__placeholder__" }]);
    // Each call returns a fresh list: mutating one does not leak.
    params.push({ name: "other" });
    expect(generateStaticParams()).toHaveLength(1);
  });

  it("renders the policy detail client component", () => {
    render(<Page />);
    expect(screen.getAllByTestId("policy-detail-client")).toHaveLength(1);
  });
});
