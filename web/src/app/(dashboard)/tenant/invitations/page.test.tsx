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

// The capability answer each test sets: the gated "View details" item reads it.
const capabilityState = { enabled: true };
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: null,
    capability: () => ({ enabled: capabilityState.enabled, reason: "not offered by this server" }),
  }),
}));

const GET_INVITATION_OP = "GET /api/v1/invitations/{id:[0-9]+}";

// The Radix menu's portal and popper do not settle in jsdom once opened, so
// the row menu renders its items inline: which items the page puts in it is
// still decided by the page's own canResend/canCancel logic.
vi.mock("@/components/ui/dropdown-menu", async (importOriginal) => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  const Item = ({
    children,
    disabled,
    "data-capability-op": op,
  }: {
    children?: React.ReactNode;
    disabled?: boolean;
    "data-capability-op"?: string;
  }) => (
    <div role="menuitem" aria-disabled={disabled ? "true" : undefined} data-capability-op={op}>
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
      expect(menuItems(row)).toEqual(["View details"]);
    },
  );

  it("keeps resend and cancel on a pending invitation", () => {
    render(<InvitationsPage />);
    const row = rowFor("pending-invitee");
    expect(within(row).getByText("Pending")).toBeTruthy();
    expect(menuItems(row)).toEqual(["View details", "Resend Invitation", "Cancel Invitation"]);
  });

  it.each([true, false])(
    "gates each row's View details on GetInvitation's route (enabled=%s)",
    (enabled) => {
      capabilityState.enabled = enabled;
      try {
        render(<InvitationsPage />);
        for (const email of ["pending-invitee", "revoked-invitee", "cancelled-invitee"]) {
          const item = within(rowFor(email)).getByText("View details").closest('[role="menuitem"]');
          expect(item?.getAttribute("data-capability-op")).toBe(GET_INVITATION_OP);
          expect(item?.getAttribute("aria-disabled")).toBe(enabled ? null : "true");
        }
      } finally {
        capabilityState.enabled = true;
      }
    },
  );
});

// Settled rows: an expired invitation can be resent, an accepted one has no
// action, and only a pending or expired invitation colours a past expiry date
// as expired (an accepted invitation's old date is not a warning).
const settledInvitations = [
  {
    id: "inv-expired",
    email: "expired-invitee",
    role: "member",
    status: "INVITATION_STATUS_EXPIRED",
    createdAt: "2019-12-01T00:00:00Z",
    expiresAt: "2020-01-01T00:00:00Z",
  },
  {
    id: "inv-accepted",
    email: "accepted-invitee",
    role: "member",
    status: "INVITATION_STATUS_ACCEPTED",
    createdAt: "2026-11-01T00:00:00Z",
    expiresAt: "2099-11-04T00:00:00Z",
  },
  {
    id: "inv-accepted-old",
    email: "accepted-old-invitee",
    role: "member",
    status: "INVITATION_STATUS_ACCEPTED",
    createdAt: "2019-12-01T00:00:00Z",
    expiresAt: "2020-01-01T00:00:00Z",
  },
];

describe("InvitationsPage states", () => {
  const original = { ...listResult };

  afterEach(() => {
    Object.assign(listResult, original);
    listResult.refetch.mockClear();
  });

  it("shows the error card and Retry calls refetch", () => {
    Object.assign(listResult, { error: new Error("boom") });
    render(<InvitationsPage />);
    expect(screen.getByText("Error loading invitations")).toBeTruthy();
    expect(screen.getByText("boom")).toBeTruthy();
    screen.getByRole("button", { name: /Retry/ }).click();
    expect(listResult.refetch).toHaveBeenCalledTimes(1);
  });

  it("shows an expired invitation as Expired with only resend", () => {
    Object.assign(listResult, { data: { invitations: settledInvitations } });
    render(<InvitationsPage />);
    const row = rowFor("expired-invitee");
    expect(within(row).getByText("Expired")).toBeTruthy();
    expect(menuItems(row)).toEqual(["View details", "Resend Invitation"]);
  });

  it("shows an accepted invitation as Accepted with no action", () => {
    Object.assign(listResult, { data: { invitations: settledInvitations } });
    render(<InvitationsPage />);
    const row = rowFor("accepted-invitee");
    expect(within(row).getByText("Accepted")).toBeTruthy();
    expect(menuItems(row)).toEqual(["View details"]);
  });

  it("colours a past expiry date only on an expired invitation", () => {
    Object.assign(listResult, { data: { invitations: settledInvitations } });
    render(<InvitationsPage />);
    const accepted = within(rowFor("accepted-old-invitee")).getByText(/2020/);
    expect(accepted.className).not.toContain("text-destructive");
    const expired = within(rowFor("expired-invitee")).getByText(/2020/);
    expect(expired.className).toContain("text-destructive");
  });
});
