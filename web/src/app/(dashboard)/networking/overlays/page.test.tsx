import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #1844: the page lists VXLAN VNIs through useOverlay (network boundary,
// mocked here) and creates a VNI from a dialog.

const { overlay, toast } = vi.hoisted(() => ({
  overlay: { listVNIs: vi.fn(), createVNI: vi.fn() },
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useOverlay: () => overlay,
  useToast: () => ({ toast }),
}));

import NetworkOverlaysPage from "./page";

const vnis = [
  { id: "vni-1", config: { vni: 10000, name: "tenant-default" }, createdAt: "2026-11-01T00:00:00Z" },
  { id: "vni-2", config: { vni: 20000 }, createdAt: "2026-11-02T00:00:00Z" },
];

function statValue(label: string): string {
  const card = screen.getByText(label).parentElement as HTMLElement;
  return (card.lastElementChild as HTMLElement).textContent ?? "";
}

async function openDialog() {
  fireEvent.click(screen.getByText("Create Overlay"));
  return screen.findByLabelText("VNI *");
}

beforeEach(() => {
  overlay.listVNIs.mockReset();
  overlay.createVNI.mockReset();
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("NetworkOverlaysPage", () => {
  it("lists each VNI as an active VXLAN overlay", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis } });
    render(<NetworkOverlaysPage />);

    expect(await screen.findByText("tenant-default")).toBeTruthy();
    expect(screen.getByText("10000")).toBeTruthy();
    expect(screen.getAllByText("vxlan")).toHaveLength(2);
    expect(screen.getAllByText("active")).toHaveLength(2);
    expect(screen.getAllByText("0 nodes")).toHaveLength(2);
    expect(statValue("Total Overlays")).toBe("2");
    expect(statValue("Active")).toBe("2");
    expect(statValue("Pending")).toBe("0");
    expect(statValue("Total Nodes")).toBe("0");
  });

  it("names an unnamed VNI after its number", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis } });
    render(<NetworkOverlaysPage />);

    expect(await screen.findByText("VNI-20000")).toBeTruthy();
  });

  it("shows the empty state when there are no VNIs", async () => {
    overlay.listVNIs.mockResolvedValue({ data: {} });
    render(<NetworkOverlaysPage />);

    expect(await screen.findByText("No network overlays found")).toBeTruthy();
    expect(statValue("Total Overlays")).toBe("0");
  });

  it("shows the empty state when listing returns an error", async () => {
    overlay.listVNIs.mockResolvedValue({ error: { message: "down", status: 503 } });
    render(<NetworkOverlaysPage />);

    expect(await screen.findByText("No network overlays found")).toBeTruthy();
  });

  it("refetches on the refresh button", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    render(<NetworkOverlaysPage />);
    await screen.findByText("No network overlays found");

    const refresh = screen.getAllByRole("button").find((b) => b.textContent === "") as HTMLElement;
    fireEvent.click(refresh);
    await waitFor(() => expect(overlay.listVNIs).toHaveBeenCalledTimes(2));
  });

  it("disables Create until a VNI is typed", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    render(<NetworkOverlaysPage />);

    const vni = await openDialog();
    const create = screen.getByRole("button", { name: "Create" }) as HTMLButtonElement;
    expect(create.disabled).toBe(true);
    fireEvent.change(vni, { target: { value: "10" } });
    expect(create.disabled).toBe(false);
  });

  it("refuses a VNI below 1 without calling the API", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    render(<NetworkOverlaysPage />);

    fireEvent.change(await openDialog(), { target: { value: "0" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Invalid VNI", variant: "destructive" }));
    expect(overlay.createVNI).not.toHaveBeenCalled();
  });

  it("refuses a negative VNI", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    render(<NetworkOverlaysPage />);

    fireEvent.change(await openDialog(), { target: { value: "-5" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Invalid VNI", variant: "destructive" }));
    expect(overlay.createVNI).not.toHaveBeenCalled();
  });

  it("creates a named VNI, toasts, closes and refetches", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    overlay.createVNI.mockResolvedValue({});
    render(<NetworkOverlaysPage />);
    await waitFor(() => expect(overlay.listVNIs).toHaveBeenCalledTimes(1));

    fireEvent.change(await openDialog(), { target: { value: "4242" } });
    fireEvent.change(screen.getByLabelText("Name (optional)"), { target: { value: "lab" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(overlay.createVNI).toHaveBeenCalledWith({ config: { vni: 4242, name: "lab" } }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith({ title: "Overlay created", variant: "success" }));
    await waitFor(() => expect(overlay.listVNIs).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText("Create Overlay (VXLAN VNI)")).toBeNull());
  });

  it("sends no name when the name is left empty", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    overlay.createVNI.mockResolvedValue({});
    render(<NetworkOverlaysPage />);

    fireEvent.change(await openDialog(), { target: { value: "7" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(overlay.createVNI).toHaveBeenCalledWith({ config: { vni: 7, name: undefined } }));
  });

  it("toasts the error and keeps the dialog open when creation fails", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    overlay.createVNI.mockRejectedValue(new Error("VNI in use"));
    render(<NetworkOverlaysPage />);

    fireEvent.change(await openDialog(), { target: { value: "9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to create overlay",
        description: "VNI in use",
        variant: "destructive",
      }),
    );
    expect(screen.getByText("Create Overlay (VXLAN VNI)")).toBeTruthy();
  });

  it("reports a non-Error rejection as Unknown error", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    overlay.createVNI.mockRejectedValue("nope");
    render(<NetworkOverlaysPage />);

    fireEvent.change(await openDialog(), { target: { value: "9" } });
    fireEvent.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ description: "Unknown error" })),
    );
  });

  it("closes the dialog on Cancel", async () => {
    overlay.listVNIs.mockResolvedValue({ data: { vnis: [] } });
    render(<NetworkOverlaysPage />);

    await openDialog();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByText("Create Overlay (VXLAN VNI)")).toBeNull());
    expect(overlay.createVNI).not.toHaveBeenCalled();
  });
});
