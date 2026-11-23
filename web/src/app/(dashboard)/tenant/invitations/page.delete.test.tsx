import * as React from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import InvitationsPage from "./page";

// Every non-pending row offers Delete Invitation (#2056): it asks for
// confirmation, then deletes the record through useInvitation().remove. The
// item is gated on the DELETE route: when the server does not offer the op the
// item stays in place, disabled, with the server's reason as its title.
const invitations = [
  {
    id: "inv-pending",
    email: "pending-invitee",
    role: "member",
    status: "INVITATION_STATUS_PENDING",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
  {
    id: "inv-revoked",
    email: "revoked-invitee",
    role: "viewer",
    status: "INVITATION_STATUS_REVOKED",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
];

const DELETE_OP = "DELETE /api/v1/invitations/{id:[0-9]+}";

// Hook results are stable objects: a fresh `data` per render would re-key the
// page's memoised rows and the table on every pass.
const create = { mutateAsync: vi.fn(), isLoading: false };
const revoke = { mutateAsync: vi.fn(), isLoading: false };
const remove = { mutateAsync: vi.fn(), isLoading: false };
const invitationHooks = { create, revoke, resend: create, remove };
const listResult = { data: { invitations }, isLoading: false, error: null, refetch: vi.fn() };
const toastResult = { toast: vi.fn() };
const authResult = { isLoading: false };

const caps = vi.hoisted(() => ({ capability: vi.fn() }));

vi.mock("@/hooks/use-capabilities", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/use-capabilities")>()),
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useInvitation: () => invitationHooks,
  useInvitationList: () => listResult,
}));

// The Radix menu's portal and popper do not settle in jsdom once opened, so
// the row menu renders its items inline. The item keeps the props Gated
// gives it, and a disabled item fires no click, as Radix's does not.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({
    children,
    disabled,
    onClick,
    className: _className,
    ...rest
  }: React.HTMLAttributes<HTMLDivElement> & { disabled?: boolean }) => (
    <div
      role="menuitem"
      aria-disabled={disabled ? "true" : undefined}
      onClick={disabled ? undefined : onClick}
      {...rest}
    >
      {children}
    </div>
  );
  return {
    ...(await importOriginal<typeof import("@/components/ui/dropdown-menu")>()),
    DropdownMenu: Pass,
    DropdownMenuTrigger: Pass,
    DropdownMenuContent: Pass,
    DropdownMenuLabel: Pass,
    DropdownMenuSeparator: () => null,
    DropdownMenuItem: Item,
  };
});

function offer(off: string[]) {
  caps.capability.mockImplementation((op: string) =>
    off.includes(op)
      ? { enabled: false, reason: "not-configured: invitations" }
      : { enabled: true },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  offer([]);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function rowFor(email: string): HTMLElement {
  const row = screen.getByText(email).closest("tr");
  if (!row) throw new Error(`no table row for ${email}`);
  return row;
}

function deleteItem(): HTMLElement {
  return within(rowFor("revoked-invitee")).getByRole("menuitem", { name: /Delete Invitation/ });
}

describe("InvitationsPage delete", () => {
  it("deletes a revoked invitation after confirmation", async () => {
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    remove.mutateAsync.mockResolvedValue(undefined);
    render(<InvitationsPage />);
    const item = deleteItem();
    expect(item.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(item.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(item);
    expect(confirm).toHaveBeenCalledTimes(1);
    await vi.waitFor(() => expect(remove.mutateAsync).toHaveBeenCalledWith("inv-revoked"));
    expect(revoke.mutateAsync).not.toHaveBeenCalled();
    await vi.waitFor(() =>
      expect(toastResult.toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Invitation deleted" }),
      ),
    );
  });

  it("sends nothing when the confirmation is declined", () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    render(<InvitationsPage />);
    fireEvent.click(deleteItem());
    expect(remove.mutateAsync).not.toHaveBeenCalled();
  });

  it("shows the server's error when the delete fails", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    remove.mutateAsync.mockRejectedValue(new Error("invitation not found"));
    render(<InvitationsPage />);
    fireEvent.click(deleteItem());
    await vi.waitFor(() =>
      expect(toastResult.toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Failed to delete invitation",
          description: "invitation not found",
          variant: "destructive",
        }),
      ),
    );
  });

  it("offers no Delete Invitation on a pending row", () => {
    render(<InvitationsPage />);
    expect(
      within(rowFor("pending-invitee")).queryByRole("menuitem", { name: /Delete Invitation/ }),
    ).toBeNull();
  });

  it("withholds Delete Invitation when the server does not offer it", () => {
    offer([DELETE_OP]);
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    render(<InvitationsPage />);
    const item = deleteItem();
    expect(item.getAttribute("data-capability-op")).toBe(DELETE_OP);
    expect(item.getAttribute("data-capability-enabled")).toBe("false");
    expect(item.getAttribute("aria-disabled")).toBe("true");
    expect(item.getAttribute("title")).toBe("not-configured: invitations");
    fireEvent.click(item);
    expect(confirm).not.toHaveBeenCalled();
    expect(remove.mutateAsync).not.toHaveBeenCalled();
  });
});
