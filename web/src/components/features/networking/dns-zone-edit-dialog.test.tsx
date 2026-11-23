import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { dns, toast, off } = vi.hoisted(() => ({
  dns: { updateZone: vi.fn() },
  toast: vi.fn(),
  off: new Set<string>(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNS: () => dns,
  useToast: () => ({ toast }),
}));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: dns" } : { enabled: true },
  }),
}));

const UPDATE_ZONE_OP = "PUT /api/v1/dns/zones/{zone}";

import { DNSZoneEditDialog } from "./dns-zone-edit-dialog";

function renderDialog(onSaved = vi.fn()) {
  render(
    <DNSZoneEditDialog zoneName="example.com" ttl={3600} description="lab zone" onSaved={onSaved} />,
  );
  return onSaved;
}

function editButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Edit Zone" }) as HTMLButtonElement;
}

function ttlInput(): HTMLInputElement {
  return screen.getByRole("spinbutton", { name: "TTL" }) as HTMLInputElement;
}

function descriptionInput(): HTMLInputElement {
  return screen.getByRole("textbox", { name: "Description" }) as HTMLInputElement;
}

beforeEach(() => {
  dns.updateZone.mockReset();
  toast.mockReset();
  dns.updateZone.mockResolvedValue({ data: {} });
});

afterEach(() => {
  cleanup();
  off.clear();
});

describe("DNSZoneEditDialog", () => {
  it("opens with the zone's current TTL and description", async () => {
    renderDialog();
    fireEvent.click(editButton());

    expect(await screen.findByRole("dialog", { name: "Edit zone example.com" })).toBeTruthy();
    expect(ttlInput().value).toBe("3600");
    expect(descriptionInput().value).toBe("lab zone");
  });

  it("saves the new TTL and description through dns.updateZone", async () => {
    const onSaved = renderDialog();
    fireEvent.click(editButton());
    await screen.findByRole("dialog", { name: "Edit zone example.com" });

    fireEvent.change(ttlInput(), { target: { value: "300" } });
    fireEvent.change(descriptionInput(), { target: { value: "edge zone" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(onSaved).toHaveBeenCalledTimes(1));
    expect(dns.updateZone).toHaveBeenCalledTimes(1);
    expect(dns.updateZone).toHaveBeenCalledWith({
      name: "example.com",
      ttl: 300,
      description: "edge zone",
    });
    expect(toast).toHaveBeenCalled();
    for (const [arg] of toast.mock.calls) {
      expect(arg.variant).not.toBe("destructive");
    }
  });

  it("refuses a TTL outside 60-86400 without a request", async () => {
    renderDialog();
    fireEvent.click(editButton());
    await screen.findByRole("dialog", { name: "Edit zone example.com" });

    fireEvent.change(ttlInput(), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    expect(await screen.findByText(/TTL must be .*60/)).toBeTruthy();
    expect(dns.updateZone).not.toHaveBeenCalled();
  });

  it("withholds the control the server does not offer", () => {
    off.add(UPDATE_ZONE_OP);
    renderDialog();

    const button = editButton();
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: dns");
    expect(button.getAttribute("data-capability-enabled")).toBe("false");

    fireEvent.click(button);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("shows a refused update as a destructive toast", async () => {
    dns.updateZone.mockResolvedValue({
      success: false,
      error: { code: "PERMISSION_DENIED", message: "zone is read-only" },
    });
    const onSaved = renderDialog();
    fireEvent.click(editButton());
    await screen.findByRole("dialog", { name: "Edit zone example.com" });

    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          description: expect.stringContaining("zone is read-only"),
          variant: "destructive",
        }),
      ),
    );
    expect(onSaved).not.toHaveBeenCalled();
  });
});
