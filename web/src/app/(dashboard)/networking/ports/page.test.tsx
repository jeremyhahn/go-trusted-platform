import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1845: the page reads bridges and ports through the SDN client. These tests
// stub that client (the network boundary) and the toast hook.

const toast = vi.fn();
const sdn = {
  listBridges: vi.fn(),
  listPorts: vi.fn(),
  addPort: vi.fn(),
  deletePort: vi.fn(),
};

vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast }) }));
vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
}));

import SDNPortsPage from "./page";

describe("SDNPortsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    for (const fn of Object.values(sdn)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("shows the error state when the bridges cannot be listed", async () => {
    sdn.listBridges.mockResolvedValue({ success: false, error: { message: "sdn unavailable" } });

    render(<SDNPortsPage />);

    expect(await screen.findByText("Error Loading Ports")).toBeTruthy();
  });
});
