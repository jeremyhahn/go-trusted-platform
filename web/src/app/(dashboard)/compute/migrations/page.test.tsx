import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import MigrationsPage from "./page";

// #1727: the daemon overwrites the receiver's acceleration setting with the
// spec's, so the form sends the source guest's KVM setting (on by default).

const ops = {
  pending: null,
  prepareMigration: vi.fn().mockResolvedValue({ receiverId: "rx-1" }),
  finalizeMigration: vi.fn(),
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useVMOperations: () => ops,
  useToast: () => ({ toast: vi.fn() }),
}));

function fillSpec() {
  fireEvent.change(screen.getByLabelText("Guest name"), { target: { value: "ops-vm" } });
  fireEvent.change(screen.getByLabelText("Memory MB"), { target: { value: "4096" } });
  fireEvent.change(screen.getByLabelText("CPUs"), { target: { value: "2" } });
}

describe("MigrationsPage receiver spec", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("sends KVM acceleration on by default", async () => {
    render(<MigrationsPage />);
    fillSpec();
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));

    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(1));
    expect(ops.prepareMigration.mock.calls[0][0].spec.enableKvm).toBe(true);
  });

  it("sends KVM acceleration off when unchecked", async () => {
    render(<MigrationsPage />);
    fillSpec();
    fireEvent.click(screen.getByLabelText("KVM acceleration"));
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));

    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(1));
    expect(ops.prepareMigration.mock.calls[0][0].spec.enableKvm).toBe(false);
  });
});
