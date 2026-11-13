import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { VMForm } from "./vm-form";

// #1816: VMForm validates with zod, maps the form values onto the SDK
// CreateVMRequest (one qcow2 disk sized in whole GB) and reports the outcome
// through the toast. Only the compute client and the toast are stubbed.

const compute = {
  createVM: vi.fn(),
};
const toastMock = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCompute: () => compute,
  useToast: () => ({ toast: toastMock }),
}));

function setup(open = true) {
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(<VMForm open={open} onOpenChange={onOpenChange} onSuccess={onSuccess} />);
  return { onOpenChange, onSuccess };
}

function setName(value: string) {
  fireEvent.change(screen.getByPlaceholderText("my-vm"), { target: { value } });
}

/** The vCPU, memory and storage inputs, in that order. */
function numberInputs(): HTMLInputElement[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>('input[type="number"]'));
}

function submit() {
  return act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Create VM" }));
  });
}

describe("VMForm", () => {
  beforeEach(() => {
    compute.createVM.mockReset();
    toastMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders nothing while closed", () => {
    setup(false);
    expect(screen.queryByText("Create Virtual Machine")).toBeNull();
  });

  it("opens with 2 vCPUs, 2048 MB of memory and 20480 MB of storage", () => {
    setup();
    expect(screen.getByText("Create Virtual Machine")).toBeTruthy();
    expect(numberInputs().map((i) => i.value)).toEqual(["2", "2048", "20480"]);
    expect(screen.getByPlaceholderText("Optional description")).toBeTruthy();
  });

  it("refuses an empty name and sends nothing", async () => {
    setup();
    await submit();
    await waitFor(() => expect(screen.getByText("Name is required")).toBeTruthy());
    expect(compute.createVM).not.toHaveBeenCalled();
  });

  it("refuses a name longer than 64 characters", async () => {
    setup();
    setName("v".repeat(65));
    await submit();
    await waitFor(() => expect(screen.getByText("Name too long")).toBeTruthy());
    expect(compute.createVM).not.toHaveBeenCalled();
  });

  it.each([
    ["no vCPU", 0, "0"],
    ["65 vCPUs", 0, "65"],
    ["a blank vCPU count", 0, ""],
    ["256 MB of memory", 1, "256"],
    ["more than 512 GB of memory", 1, "524289"],
    ["512 MB of storage", 2, "512"],
    ["more than 10 TB of storage", 2, "10485761"],
  ])("refuses %s", async (_label, index, value) => {
    setup();
    setName("vm1");
    fireEvent.change(numberInputs()[index], { target: { value } });
    await submit();
    expect(compute.createVM).not.toHaveBeenCalled();
  });

  it("sends the mapped request, then toasts, closes, resets and calls onSuccess", async () => {
    compute.createVM.mockResolvedValue({ success: true, data: { id: "vm-1" } });
    const { onOpenChange, onSuccess } = setup();
    setName("db");
    fireEvent.change(screen.getByPlaceholderText("Optional description"), {
      target: { value: "database host" },
    });
    const [vcpus, memory, storage] = numberInputs();
    fireEvent.change(vcpus, { target: { value: "4" } });
    fireEvent.change(memory, { target: { value: "8192" } });
    fireEvent.change(storage, { target: { value: "1025" } });

    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(compute.createVM).toHaveBeenCalledWith({
      config: {
        name: "db",
        cpu: { cores: 4 },
        memory: { sizeMb: 8192 },
        // 1025 MB rounds up to 2 GB.
        disks: [{ path: "/data/db.qcow2", type: "DISK_TYPE_QCOW2", sizeGb: 2 }],
        networks: [],
      },
    });
    expect(toastMock).toHaveBeenCalledWith({
      title: "Success",
      description: "Virtual machine created successfully",
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect((screen.getByPlaceholderText("my-vm") as HTMLInputElement).value).toBe("");
  });

  it("sends the defaults at the lower bounds", async () => {
    compute.createVM.mockResolvedValue({ success: true, data: {} });
    const { onSuccess } = setup();
    setName("tiny");
    const [vcpus, memory, storage] = numberInputs();
    fireEvent.change(vcpus, { target: { value: "1" } });
    fireEvent.change(memory, { target: { value: "512" } });
    fireEvent.change(storage, { target: { value: "1024" } });

    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    expect(compute.createVM).toHaveBeenCalledWith({
      config: {
        name: "tiny",
        cpu: { cores: 1 },
        memory: { sizeMb: 512 },
        disks: [{ path: "/data/tiny.qcow2", type: "DISK_TYPE_QCOW2", sizeGb: 1 }],
        networks: [],
      },
    });
  });

  it("toasts the error response and stays open", async () => {
    compute.createVM.mockResolvedValue({
      success: false,
      error: { code: "RESOURCE_EXHAUSTED", message: "no capacity" },
    });
    const { onOpenChange, onSuccess } = setup();
    setName("vm1");

    await submit();

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Error",
        description: "Failed to create VM: no capacity",
        variant: "destructive",
      })
    );
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("toasts a thrown error", async () => {
    compute.createVM.mockRejectedValue(new Error("network down"));
    setup();
    setName("vm1");

    await submit();

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Failed to create VM: network down" })
      )
    );
  });

  it("disables both buttons and says Creating... while the request runs", async () => {
    compute.createVM.mockReturnValue(new Promise(() => {}));
    setup();
    setName("vm1");

    await submit();

    const creating = await screen.findByRole("button", { name: "Creating..." });
    expect((creating as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("closes through Cancel without sending", () => {
    const { onOpenChange } = setup();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(compute.createVM).not.toHaveBeenCalled();
  });
});
