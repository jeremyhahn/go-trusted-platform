import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1727: MigrateVM returns only after the transfer and finalization, so the
// hook gives the request a timeout far above the 30 s client default.

const DELAY_MS = 31000;

const compute = {
  migrateVM: vi.fn(
    () =>
      new Promise((resolve) => {
        setTimeout(() => resolve({ success: true, data: {} }), DELAY_MS);
      })
  ),
  listVMs: vi.fn(),
};

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  useCompute: () => compute,
}));

vi.mock("./use-toast", () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

import { MIGRATION_TIMEOUT_MS, useVMOperations } from "./use-vm-operations";

describe("useVMOperations migrate", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("waits past 30 s for a migration and sends the migration timeout", async () => {
    const { result } = renderHook(() => useVMOperations());

    let done: Promise<boolean> | undefined;
    act(() => {
      done = result.current.migrate("vm-1", "dest", true);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(DELAY_MS);
    });

    await expect(done).resolves.toBe(true);
    expect(MIGRATION_TIMEOUT_MS).toBeGreaterThan(30000);
    expect(compute.migrateVM).toHaveBeenCalledWith(expect.objectContaining({ vmId: "vm-1" }), {
      timeoutMs: MIGRATION_TIMEOUT_MS,
    });
  });
});

// #1742: Commit Migration checks that the received guest is in the host's VM
// registry; the daemon's VM carries its name in config, and ListVMs pages.
describe("useVMOperations isRegistered", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  const page = (names: string[], pageNo: number, totalPages: number) => ({
    success: true,
    data: {
      vms: names.map((name) => ({ id: `id-${name}`, config: { name } })),
      pagination: { page: pageNo, pageSize: 1, totalPages, totalItems: totalPages },
    },
  });

  it("finds the guest on a later page", async () => {
    compute.listVMs.mockResolvedValueOnce(page(["other"], 1, 2)).mockResolvedValueOnce(page(["ops-vm"], 2, 2));
    const { result } = renderHook(() => useVMOperations());

    await expect(result.current.isRegistered("ops-vm")).resolves.toBe(true);
    expect(compute.listVMs).toHaveBeenCalledTimes(2);
  });

  it("answers false when no page lists the guest", async () => {
    compute.listVMs.mockResolvedValueOnce(page(["other"], 1, 1));
    const { result } = renderHook(() => useVMOperations());

    await expect(result.current.isRegistered("ops-vm")).resolves.toBe(false);
  });

  it("answers false when ListVMs fails", async () => {
    compute.listVMs.mockResolvedValueOnce({ success: false, error: { message: "down" } });
    const { result } = renderHook(() => useVMOperations());

    await expect(result.current.isRegistered("ops-vm")).resolves.toBe(false);
  });
});
