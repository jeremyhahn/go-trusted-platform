import * as React from "react";
import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import InvitationsPage from "./page";

// The page normalises the server's protobuf status enum to the UI strings.
// These rows pin that INVITATION_STATUS_REVOKED and the CANCELLED variant both
// render as "Revoked" with no resend or cancel action, and that a pending row
// keeps both actions.
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
    role: "member",
    status: "INVITATION_STATUS_REVOKED",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
  {
    id: "inv-cancelled",
    email: "cancelled-invitee",
    role: "member",
    status: "INVITATION_STATUS_CANCELLED",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
];

// Hook results are stable objects: a fresh `data` per render would re-key the
// page's memoised rows and the table on every pass.
const mutation = { mutateAsync: vi.fn(), isLoading: false };
const invitationHooks = { create: mutation, revoke: mutation, resend: mutation };
const listResult = { data: { invitations }, isLoading: false, error: null, refetch: vi.fn() };
const toastResult = { toast: vi.fn() };
const authResult = { isLoading: false };

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
// the row menu renders its items inline: which items the page puts in it is
// still decided by the page's own canResend/canCancel logic.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({ children }: { children?: React.ReactNode }) => (
    <div role="menuitem">{children}</div>
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

afterEach(() => {
  cleanup();
});

function rowFor(email: string): HTMLElement {
  const row = screen.getByText(email).closest("tr");
  if (!row) throw new Error(`no table row for ${email}`);
  return row;
}

function menuItems(row: HTMLElement): string[] {
  return within(row)
    .getAllByRole("menuitem")
    .map((item) => item.textContent?.trim() ?? "");
}

describe("InvitationsPage status mapping", () => {
  it.each(["revoked-invitee", "cancelled-invitee"])(
    "shows %s as Revoked with no resend or cancel action",
    (email) => {
      render(<InvitationsPage />);
      const row = rowFor(email);
      expect(within(row).getByText("Revoked")).toBeTruthy();
      expect(menuItems(row)).toEqual(["No actions available"]);
    },
  );

  it("keeps resend and cancel on a pending invitation", () => {
    render(<InvitationsPage />);
    const row = rowFor("pending-invitee");
    expect(within(row).getByText("Pending")).toBeTruthy();
    expect(menuItems(row)).toEqual(["Resend Invitation", "Cancel Invitation"]);
  });
});
