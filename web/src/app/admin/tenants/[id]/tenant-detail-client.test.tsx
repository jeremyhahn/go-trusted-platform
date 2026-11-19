import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2023 Codex round 1: TenantGRPCServer.Sync reports a failed run in
// status.success=false inside an HTTP 200 response, so the page must read the
// in-band status rather than the SDK's outer success flag.

const syncTenants = vi.fn();

vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "t-1" }),
  usePathname: () => "/admin/tenants/t-1/",
}));

vi.mock("@/hooks", () => ({
  useApi: () => ({
    data: { tenant: { tenantId: "t-1", name: "Acme", state: "ACTIVE" } },
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
  useTenant: () => ({ syncTenants }),
}));

import TenantDetailClient from "./tenant-detail-client";

async function clickSync() {
  render(<TenantDetailClient />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Sync tenants" }));
  });
}

describe("TenantDetailClient sync", () => {
  beforeEach(() => syncTenants.mockReset());
  afterEach(() => cleanup());

  it("shows the in-band failure message when the sync run fails", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: false, message: "sync backend down" } },
    });
    await clickSync();
    const result = screen.getByTestId("action-result");
    expect(result.textContent).toContain("sync backend down");
    expect(result.textContent).not.toContain("Tenants synced");
  });

  it("reports success when the sync run succeeds", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" } },
    });
    await clickSync();
    expect(screen.getByTestId("action-result").textContent).toBe("Tenants synced");
  });
});
