import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import React from "react";

vi.mock("@/utils/auth-factors-api", () => ({
  authFactorsApi: { add: vi.fn(), rotate: vi.fn() },
  isFIDO2Available: vi.fn(() => true),
}));

import { AddFactorWizard } from "./add-factor-wizard";

describe("AddFactorWizard", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });
  afterEach(() => {
    cleanup();
  });

  it("renders nothing when closed", () => {
    render(
      <AddFactorWizard
        open={false}
        onOpenChange={vi.fn()}
        userId="u1"
        onAdded={vi.fn()}
      />,
    );
    expect(screen.queryByText("Add authentication factor")).toBeNull();
  });

  it("opens on step 1 with the add title", () => {
    render(
      <AddFactorWizard
        open
        onOpenChange={vi.fn()}
        userId="u1"
        onAdded={vi.fn()}
      />,
    );
    expect(screen.getByText("Add authentication factor")).toBeTruthy();
  });
});
