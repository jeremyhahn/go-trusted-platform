import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ContainerForm } from "./container-form";

// #1816: ContainerForm validates with zod, maps the form values onto the SDK
// CreateContainerRequest and reports the outcome through the toast. Only the
// compute client and the toast are stubbed; useMutation is the real one.

const compute = {
  createContainer: vi.fn(),
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
  render(<ContainerForm open={open} onOpenChange={onOpenChange} onSuccess={onSuccess} />);
  return { onOpenChange, onSuccess };
}

function type(placeholder: string, value: string) {
  fireEvent.change(screen.getByPlaceholderText(placeholder), { target: { value } });
}

function submit() {
  return act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Create Container" }));
  });
}

function numberInputs(): HTMLInputElement[] {
  return Array.from(document.querySelectorAll<HTMLInputElement>('input[type="number"]'));
}

describe("ContainerForm", () => {
  beforeEach(() => {
    compute.createContainer.mockReset();
    toastMock.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("renders nothing while closed", () => {
    setup(false);
    expect(screen.queryByText("Create a new container from a Docker image.")).toBeNull();
  });

  it("opens with the default memory and CPU shares and no port mapping", () => {
    setup();
    expect(screen.getByText("Create a new container from a Docker image.")).toBeTruthy();
    const [memory, cpu] = numberInputs();
    expect(memory.value).toBe("512");
    expect(cpu.value).toBe("512");
    expect(screen.queryByPlaceholderText("Host")).toBeNull();
  });

  it("refuses an empty name and image and sends nothing", async () => {
    setup();
    await submit();
    await waitFor(() => expect(screen.getByText("Name is required")).toBeTruthy());
    expect(screen.getByText("Image is required")).toBeTruthy();
    expect(compute.createContainer).not.toHaveBeenCalled();
  });

  it("refuses a name longer than 64 characters", async () => {
    setup();
    type("my-container", "x".repeat(65));
    type("nginx:latest", "nginx:latest");
    await submit();
    await waitFor(() => expect(screen.getByText("Name too long")).toBeTruthy());
    expect(compute.createContainer).not.toHaveBeenCalled();
  });

  it("refuses memory below 128 MB and CPU shares above 1024", async () => {
    setup();
    type("my-container", "web");
    type("nginx:latest", "nginx:latest");
    const [memory, cpu] = numberInputs();
    fireEvent.change(memory, { target: { value: "64" } });
    await submit();
    expect(compute.createContainer).not.toHaveBeenCalled();

    fireEvent.change(memory, { target: { value: "256" } });
    fireEvent.change(cpu, { target: { value: "2048" } });
    await submit();
    expect(compute.createContainer).not.toHaveBeenCalled();
  });

  it("refuses a port mapping outside 1-65535", async () => {
    setup();
    type("my-container", "web");
    type("nginx:latest", "nginx:latest");
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByPlaceholderText("Host"), { target: { value: "0" } });
    await submit();
    expect(compute.createContainer).not.toHaveBeenCalled();

    fireEvent.change(screen.getByPlaceholderText("Host"), { target: { value: "65536" } });
    await submit();
    expect(compute.createContainer).not.toHaveBeenCalled();
  });

  it("sends the mapped request, then toasts, closes, resets and calls onSuccess", async () => {
    compute.createContainer.mockResolvedValue({ success: true, data: { id: "c1" } });
    const { onOpenChange, onSuccess } = setup();
    type("my-container", "web");
    type("nginx:latest", "nginx:1.27");
    type("Override default command", "nginx -g daemon");
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    fireEvent.change(screen.getByPlaceholderText("Container"), { target: { value: "443" } });
    const [, , memory, cpu] = numberInputs();
    fireEvent.change(memory, { target: { value: "1024" } });
    fireEvent.change(cpu, { target: { value: "256" } });

    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalledTimes(1));
    expect(compute.createContainer).toHaveBeenCalledWith({
      config: {
        name: "web",
        image: "nginx:1.27",
        command: ["nginx", "-g", "daemon"],
        ports: [{ containerPort: 443, hostPort: 8080, protocol: "tcp" }],
        resources: { maxMemoryMb: 1024, maxCpus: 0.25 },
      },
    });
    expect(toastMock).toHaveBeenCalledWith({
      title: "Success",
      description: "Container created successfully",
    });
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect((screen.getByPlaceholderText("my-container") as HTMLInputElement).value).toBe("");
  });

  it("omits a blank command and sends no CPU limit for zero shares", async () => {
    compute.createContainer.mockResolvedValue({ success: true, data: {} });
    const { onSuccess } = setup();
    type("my-container", "web");
    type("nginx:latest", "nginx");
    const [, cpu] = numberInputs();
    fireEvent.change(cpu, { target: { value: "0" } });

    await submit();

    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
    expect(compute.createContainer).toHaveBeenCalledWith({
      config: {
        name: "web",
        image: "nginx",
        command: undefined,
        ports: [],
        resources: { maxMemoryMb: 512, maxCpus: undefined },
      },
    });
  });

  it("removes a port mapping it added", () => {
    setup();
    fireEvent.click(screen.getByRole("button", { name: /add port/i }));
    const host = screen.getByPlaceholderText("Host");
    const row = host.closest("div.flex.gap-2") as HTMLElement;
    const buttons = row.querySelectorAll("button");
    fireEvent.click(buttons[buttons.length - 1]);
    expect(screen.queryByPlaceholderText("Host")).toBeNull();
  });

  it("toasts the error and stays open when the create fails", async () => {
    compute.createContainer.mockResolvedValue({
      success: false,
      error: { code: "ALREADY_EXISTS", message: "name taken" },
    });
    const { onOpenChange, onSuccess } = setup();
    type("my-container", "web");
    type("nginx:latest", "nginx");

    await submit();

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith({
        title: "Error",
        description: "Failed to create container: name taken",
        variant: "destructive",
      })
    );
    expect(onSuccess).not.toHaveBeenCalled();
    expect(onOpenChange).not.toHaveBeenCalled();
  });

  it("toasts a thrown error", async () => {
    compute.createContainer.mockRejectedValue(new Error("network down"));
    setup();
    type("my-container", "web");
    type("nginx:latest", "nginx");

    await submit();

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ description: "Failed to create container: network down" })
      )
    );
  });

  it("disables both buttons and says Creating... while the request runs", async () => {
    compute.createContainer.mockReturnValue(new Promise(() => {}));
    setup();
    type("my-container", "web");
    type("nginx:latest", "nginx");

    await submit();

    const creating = await screen.findByRole("button", { name: "Creating..." });
    expect((creating as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Cancel" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("closes through Cancel without sending", () => {
    const { onOpenChange } = setup();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(compute.createContainer).not.toHaveBeenCalled();
  });
});
