import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import InvitationDetailClient from "./invitation-detail-client";

// The detail page deletes a non-pending invitation through the SDK hook,
// gated on the delete route, after a confirm, and returns to the list (#2056).
const DELETE_OP = "DELETE /api/v1/invitations/{id:[0-9]+}";

const pending = {
  invitation: {
    id: "42",
    email: "invitee@example.com",
    role: "member",
    status: "INVITATION_STATUS_PENDING",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
};
const revoked = {
  invitation: { ...pending.invitation, status: "INVITATION_STATUS_REVOKED" },
};
const accepted = {
  invitation: { ...pending.invitation, status: "INVITATION_STATUS_ACCEPTED" },
};

// Hook results are stable objects across renders.
const revoke = { mutateAsync: vi.fn(), isLoading: false };
const remove = { mutateAsync: vi.fn(), isLoading: false };
const invitationHooks = { revoke, remove };
const toastResult = { toast: vi.fn() };
const detail = vi.hoisted(() => ({
  result: { data: undefined as unknown, isLoading: false, error: null, refetch: vi.fn() },
}));
const caps = vi.hoisted(() => ({ capability: vi.fn() }));
const nav = vi.hoisted(() => ({ push: vi.fn() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/tenant/invitations/42/",
  useRouter: () => ({ push: nav.push }),
}));

vi.mock("@/hooks/use-capabilities", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/use-capabilities")>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useInvitationById: () => detail.result,
  useInvitation: () => invitationHooks,
  useToast: () => toastResult,
}));

// A promise React's `use` reads at once, with no suspend.
function settled<T>(value: T): Promise<T> {
  return Object.assign(Promise.resolve(value), { status: "fulfilled", value });
}

function offer(off: string[]) {
  caps.capability.mockImplementation((op: string) =>
    off.includes(op) ? { enabled: false, reason: "not-configured: invitations" } : { enabled: true },
  );
}

function renderPage() {
  render(<InvitationDetailClient params={settled({ id: "42" })} />);
}

function withData(data: unknown) {
  detail.result = { data, isLoading: false, error: null, refetch: vi.fn() };
}

beforeEach(() => {
  vi.clearAllMocks();
  offer([]);
  withData(revoked);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("InvitationDetailClient delete", () => {
  it("deletes a revoked invitation after the confirm and returns to the list", async () => {
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    remove.mutateAsync.mockResolvedValue(undefined);
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete Invitation" }));
    });
    expect(confirm).toHaveBeenCalledWith(
      "Delete the invitation to invitee@example.com? The record is removed.",
    );
    expect(remove.mutateAsync).toHaveBeenCalledWith("42");
    expect(toastResult.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
    expect(nav.push).toHaveBeenCalledWith("/tenant/invitations");
  });

  it("does not delete when the confirm is declined", async () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete Invitation" }));
    });
    expect(remove.mutateAsync).not.toHaveBeenCalled();
    expect(toastResult.toast).not.toHaveBeenCalled();
    expect(nav.push).not.toHaveBeenCalled();
  });

  it("shows no Delete Invitation for a pending invitation", () => {
    withData(pending);
    renderPage();
    expect(screen.getByRole("button", { name: "Revoke" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete Invitation" })).toBeNull();
  });

  it("offers Delete Invitation for an accepted invitation", () => {
    withData(accepted);
    renderPage();
    expect(screen.getByRole("button", { name: "Delete Invitation" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("withholds Delete Invitation when the server does not offer it", () => {
    offer([DELETE_OP]);
    renderPage();
    const button = screen.getByRole("button", { name: "Delete Invitation" }) as HTMLButtonElement;
    expect(button.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: invitations");
  });

  it("shows a refused delete as a destructive toast", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    remove.mutateAsync.mockRejectedValue(new Error("invitation not found"));
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete Invitation" }));
    });
    expect(toastResult.toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", description: "invitation not found" }),
    );
    expect(nav.push).not.toHaveBeenCalled();
  });
});
