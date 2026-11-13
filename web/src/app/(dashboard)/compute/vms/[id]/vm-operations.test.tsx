import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { VMOperations } from "./vm-operations";

// #1727: the daemon returns no disk ID from AttachDisk and GetVM lists no
// disks, so the page sends a known ID with the attach and keeps it in the
// Disk ID field for resize and detach.

const ops = {
  pending: null,
  attachDisk: vi.fn().mockResolvedValue(true),
  resizeDisk: vi.fn().mockResolvedValue(true),
  detachDisk: vi.fn().mockResolvedValue(true),
  attest: vi.fn(),
  metrics: vi.fn(),
  createSnapshot: vi.fn(),
  getSnapshot: vi.fn(),
  migrate: vi.fn(),
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useVMOperations: () => ops,
  useToast: () => ({ toast: vi.fn() }),
}));

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

function click(name: string) {
  fireEvent.click(screen.getByRole("button", { name }));
}

describe("VMOperations disks", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("attaches under a generated ID and resizes and detaches that ID", async () => {
    render(<VMOperations vmId="vm-1" />);
    fill("Disk path", "/d/a.qcow2");
    click("Attach Disk");

    await waitFor(() => expect(ops.attachDisk).toHaveBeenCalledTimes(1));
    expect(ops.attachDisk).toHaveBeenCalledWith("vm-1", {
      id: expect.stringMatching(/^disk-[0-9a-f]{16}$/),
      path: "/d/a.qcow2",
      sizeGb: 10,
    });
    const id = ops.attachDisk.mock.calls[0][1].id as string;
    await waitFor(() => expect(screen.getByLabelText("Disk ID")).toHaveProperty("value", id));

    fill("New size GB", "64");
    click("Resize Disk");
    await waitFor(() => expect(ops.resizeDisk).toHaveBeenCalledWith("vm-1", id, 64));

    click("Detach Disk");
    fireEvent.click(await screen.findByRole("button", { name: "Confirm" }));
    await waitFor(() => expect(ops.detachDisk).toHaveBeenCalledWith("vm-1", id));
  });

  it("attaches under the ID typed in the Disk ID field", async () => {
    render(<VMOperations vmId="vm-1" />);
    fill("Disk ID", "disk-mine");
    fill("Disk path", "/d/a.qcow2");
    click("Attach Disk");

    await waitFor(() => expect(ops.attachDisk).toHaveBeenCalledTimes(1));
    expect(ops.attachDisk.mock.calls[0][1]).toMatchObject({ id: "disk-mine" });
  });
});

// #1742: the destination receiver creates a blank disk and live mode moves
// only RAM, so a live migration would resume the guest on an empty disk. The
// page migrates cold and offers no live option until the destination opens
// the source's shared backing image.
describe("VMOperations migration", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("migrates cold, never live", async () => {
    ops.migrate.mockResolvedValue(true);
    render(<VMOperations vmId="vm-1" />);
    fill("Destination host", "dest-node");
    click("Migrate VM");
    const confirm = await screen.findByRole("button", { name: "Confirm" });
    expect(screen.getByRole("dialog").textContent).not.toContain("(live)");
    fireEvent.click(confirm);

    await waitFor(() => expect(ops.migrate).toHaveBeenCalledWith("vm-1", "dest-node", false));
  });

  it("offers no live option", () => {
    render(<VMOperations vmId="vm-1" />);
    const live = screen.getByLabelText("Live") as HTMLInputElement;
    expect(live.checked).toBe(false);
    expect(live.disabled).toBe(true);
  });
});
