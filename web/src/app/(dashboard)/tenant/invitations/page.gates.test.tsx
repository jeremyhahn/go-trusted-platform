import * as React from "react";
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import InvitationsPage from "./page";

// Send Invitation and the row's Cancel Invitation are gated on their routes
// (#2056): when the server does not offer the op, the control stays in place,
// disabled, with the server's reason as its title.
const invitations = [
  {
    id: "inv-pending",
    email: "pending-invitee",
    role: "member",
    status: "INVITATION_STATUS_PENDING",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
];

const SEND_OP = "POST /api/v1/invitations";
const REVOKE_OP = "POST /api/v1/invitations/{id:[0-9]+}/revoke";

// Hook results are stable objects: a fresh `data` per render would re-key the
// page's memoised rows and the table on every pass.
const create = { mutateAsync: vi.fn(), isLoading: false };
const revoke = { mutateAsync: vi.fn(), isLoading: false };
const invitationHooks = { create, revoke, resend: create };
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

function cancelItem(): HTMLElement {
  const row = screen.getByText("pending-invitee").closest("tr");
  if (!row) throw new Error("no table row for pending-invitee");
  return within(row).getByRole("menuitem", { name: /Cancel Invitation/ });
}

describe("InvitationsPage gates", () => {
  it("withholds Send Invitation when the server does not offer it", () => {
    offer([SEND_OP]);
    render(<InvitationsPage />);
    const send = screen.getByRole("button", { name: /Send Invitation/ });
    expect(send.getAttribute("data-capability-op")).toBe(SEND_OP);
    expect(send.getAttribute("data-capability-enabled")).toBe("false");
    expect((send as HTMLButtonElement).disabled).toBe(true);
    expect(send.getAttribute("title")).toBe("not-configured: invitations");
  });

  it("withholds Cancel Invitation when the server does not offer it", () => {
    offer([REVOKE_OP]);
    const confirm = vi.fn(() => true);
    vi.stubGlobal("confirm", confirm);
    render(<InvitationsPage />);
    const item = cancelItem();
    expect(item.getAttribute("data-capability-op")).toBe(REVOKE_OP);
    expect(item.getAttribute("data-capability-enabled")).toBe("false");
    expect(item.getAttribute("aria-disabled")).toBe("true");
    expect(item.getAttribute("title")).toBe("not-configured: invitations");
    fireEvent.click(item);
    expect(confirm).not.toHaveBeenCalled();
    expect(revoke.mutateAsync).not.toHaveBeenCalled();
  });

  it("cancels a pending invitation when offered", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    revoke.mutateAsync.mockResolvedValue(undefined);
    render(<InvitationsPage />);
    const item = cancelItem();
    expect(item.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(item);
    await vi.waitFor(() => expect(revoke.mutateAsync).toHaveBeenCalledWith("inv-pending"));
    const send = screen.getByRole("button", { name: /Send Invitation/ });
    expect(send.getAttribute("data-capability-enabled")).toBe("true");
    expect((send as HTMLButtonElement).disabled).toBe(false);
  });
});
