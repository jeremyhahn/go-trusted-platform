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
