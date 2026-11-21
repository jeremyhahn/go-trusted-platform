import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import Page, { generateStaticParams } from "./page";

// The route wrapper only hands off to the client component, which has its
// own tests: stand it in with a marker.
vi.mock("./role-detail-client", () => ({
  default: () => <div data-testid="role-detail-client" />,
}));

afterEach(cleanup);

describe("roles/[id] route", () => {
  it("exports a single placeholder static param for the export build", () => {
    const params = generateStaticParams();
    expect(params).toEqual([{ id: "__placeholder__" }]);
    // Each call returns a fresh list: mutating one does not leak.
    params.push({ id: "other" });
    expect(generateStaticParams()).toHaveLength(1);
  });

  it("renders the role detail client component", () => {
    render(<Page />);
    expect(screen.getAllByTestId("role-detail-client")).toHaveLength(1);
  });
});
