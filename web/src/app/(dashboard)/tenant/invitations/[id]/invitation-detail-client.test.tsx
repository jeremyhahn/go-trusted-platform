import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import InvitationDetailClient from "./invitation-detail-client";

// The detail page revokes a pending invitation through the SDK hook, gated
// on the revoke route, after a confirm (#2056).
const REVOKE_OP = "POST /api/v1/invitations/{id:[0-9]+}/revoke";

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

// Hook results are stable objects across renders.
const revoke = { mutateAsync: vi.fn(), isLoading: false };
const invitationHooks = { revoke };
const toastResult = { toast: vi.fn() };
const detail = vi.hoisted(() => ({
  result: { data: undefined as unknown, isLoading: false, error: null, refetch: vi.fn() },
}));
const caps = vi.hoisted(() => ({ capability: vi.fn() }));

vi.mock("next/navigation", () => ({
  usePathname: () => "/tenant/invitations/42/",
  useRouter: () => ({ push: vi.fn() }),
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

beforeEach(() => {
  vi.clearAllMocks();
  offer([]);
  detail.result = { data: pending, isLoading: false, error: null, refetch: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("InvitationDetailClient revoke", () => {
  it("revokes a pending invitation after the confirm", async () => {
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    revoke.mutateAsync.mockResolvedValue(undefined);
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    });
    expect(confirm).toHaveBeenCalledWith("Revoke the invitation to invitee@example.com?");
    expect(revoke.mutateAsync).toHaveBeenCalledWith("42");
    expect(toastResult.toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "success" }));
    expect(detail.result.refetch).toHaveBeenCalled();
  });

  it("does not revoke when the confirm is declined", async () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    });
    expect(revoke.mutateAsync).not.toHaveBeenCalled();
    expect(toastResult.toast).not.toHaveBeenCalled();
  });

  it("shows no Revoke for an invitation that is not pending", () => {
    detail.result = { data: revoked, isLoading: false, error: null, refetch: vi.fn() };
    renderPage();
    expect(screen.getByTestId("invitation-status").textContent).toBe("Revoked");
    expect(screen.queryByRole("button", { name: "Revoke" })).toBeNull();
  });

  it("withholds Revoke when the server does not offer it", () => {
    offer([REVOKE_OP]);
    renderPage();
    const button = screen.getByRole("button", { name: "Revoke" }) as HTMLButtonElement;
    expect(button.getAttribute("data-capability-op")).toBe(REVOKE_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: invitations");
  });

  it("shows a refused revoke as a destructive toast", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    revoke.mutateAsync.mockRejectedValue(new Error("already accepted"));
    renderPage();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Revoke" }));
    });
    expect(toastResult.toast).toHaveBeenCalledWith(
      expect.objectContaining({ variant: "destructive", description: "already accepted" }),
    );
    expect(detail.result.refetch).not.toHaveBeenCalled();
  });
});
