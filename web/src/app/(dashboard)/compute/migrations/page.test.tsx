import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import MigrationsPage from "./page";

// #1727: the daemon overwrites the receiver's acceleration setting with the
// spec's, so the form sends the source guest's KVM setting (on by default).

const ops = {
  pending: null,
  prepareMigration: vi.fn().mockResolvedValue({ receiverId: "rx-1" }),
  finalizeMigration: vi.fn(),
  isRegistered: vi.fn().mockResolvedValue(true),
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

  // The receiver's NIC must match the source guest's, or its migration state
  // does not load: the daemon defaults an empty network mode to bridge.
  it("sends network mode bridge and no MAC address by default", async () => {
    render(<MigrationsPage />);
    fillSpec();
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));

    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(1));
    const spec = ops.prepareMigration.mock.calls[0][0].spec;
    expect(spec.networkMode).toBe("bridge");
    expect(spec).not.toHaveProperty("macAddress");
  });

  it("sends the source guest's network mode and MAC address", async () => {
    render(<MigrationsPage />);
    fillSpec();
    fireEvent.change(screen.getByLabelText("Network mode"), { target: { value: "none" } });
    fireEvent.change(screen.getByLabelText("MAC address"), { target: { value: " 52:54:00:12:34:56 " } });
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));

    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(1));
    const spec = ops.prepareMigration.mock.calls[0][0].spec;
    expect(spec.networkMode).toBe("none");
    expect(spec.macAddress).toBe("52:54:00:12:34:56");
  });

  // #1742: the receiver creates a blank disk and live mode moves only RAM, so
  // the page prepares cold receivers only until the receiver opens the
  // source's shared backing image.
  it("prepares a cold receiver and offers no live mode", async () => {
    render(<MigrationsPage />);
    fillSpec();
    const live = screen.getByRole("option", { name: "live" }) as HTMLOptionElement;
    expect(live.disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));

    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(1));
    expect(ops.prepareMigration.mock.calls[0][0].mode).toBe("cold");
  });
});

// #1727: each receiver holds a QEMU process until finalized, so the page keeps
// one outstanding receiver and refuses another prepare until it is finalized.
describe("MigrationsPage receivers", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("disables Prepare Migration while a receiver is outstanding", async () => {
    render(<MigrationsPage />);
    fillSpec();
    const prepare = screen.getByRole("button", { name: "Prepare Migration" }) as HTMLButtonElement;
    fireEvent.click(prepare);

    await waitFor(() => expect(screen.getByTestId("migration-receiver").textContent).toContain("rx-1"));
    expect(prepare.disabled).toBe(true);
    fireEvent.click(prepare);
    expect(ops.prepareMigration).toHaveBeenCalledTimes(1);
  });

  it("enables Prepare Migration again once the receiver is finalized", async () => {
    ops.finalizeMigration.mockResolvedValue({});
    render(<MigrationsPage />);
    fillSpec();
    const prepare = screen.getByRole("button", { name: "Prepare Migration" }) as HTMLButtonElement;
    fireEvent.click(prepare);
    await waitFor(() => expect(prepare.disabled).toBe(true));

    fireEvent.click(screen.getByRole("button", { name: "Commit Migration" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm" }));

    await waitFor(() => expect(ops.finalizeMigration).toHaveBeenCalledWith("rx-1", true));
    await waitFor(() => expect(prepare.disabled).toBe(false));
    fireEvent.click(prepare);
    await waitFor(() => expect(ops.prepareMigration).toHaveBeenCalledTimes(2));
  });
});

// #1742: finalize can answer success while the received guest is missing
// from the host's VM registry, so Commit Migration reports success only when
// finalize succeeded and ListVMs lists the guest.
describe("MigrationsPage commit", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    ops.isRegistered.mockResolvedValue(true);
  });

  async function prepareAndCommit() {
    render(<MigrationsPage />);
    fillSpec();
    fireEvent.click(screen.getByRole("button", { name: "Prepare Migration" }));
    await waitFor(() => expect(screen.getByTestId("migration-receiver").textContent).toContain("rx-1"));
    fireEvent.click(screen.getByRole("button", { name: "Commit Migration" }));
    fireEvent.click(await screen.findByRole("button", { name: "Confirm" }));
    return screen.findByTestId("migration-finalize-result");
  }

  it("reports the commit once the guest is registered", async () => {
    ops.finalizeMigration.mockResolvedValue({ status: { success: true, message: "" } });
    const result = await prepareAndCommit();

    await waitFor(() => expect(ops.isRegistered).toHaveBeenCalledWith("ops-vm"));
    expect(result.textContent).toBe("Receiver rx-1 committed: VM ops-vm registered");
  });

  it("reports a failure when the committed guest is not registered", async () => {
    ops.finalizeMigration.mockResolvedValue({ status: { success: true, message: "" } });
    ops.isRegistered.mockResolvedValue(false);
    const result = await prepareAndCommit();

    await waitFor(() => expect(result.textContent).toContain("not registered"));
    expect(result.textContent).not.toContain("committed:");
  });

  it("reports a failure when finalize answers an unsuccessful status", async () => {
    ops.finalizeMigration.mockResolvedValue({ status: { success: false, message: "resume refused" } });
    const result = await prepareAndCommit();

    await waitFor(() => expect(result.textContent).toBe("Receiver rx-1 commit failed: resume refused"));
    expect(ops.isRegistered).not.toHaveBeenCalled();
  });
});
