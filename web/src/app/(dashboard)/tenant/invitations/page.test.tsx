import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
const authResult = { isLoading: false, tenantId: "tenant-1" };
// #1992: the page offers the tenant's IAM role names in the invitation form.
const iamRoles = ["so", "admin", "operator", "user", "auditor", "custodian"];
const rolesResponse = () =>
  Promise.resolve({ success: true, data: { roles: iamRoles.map((name) => ({ id: name, name })) } });
const listRoles = vi.fn(rolesResponse);
const iamResult = { listRoles };

// A small stand-in for the SDK's useApi: it runs the fetcher on mount, keeps
// the unwrapped data, the error of a rejected fetch and the loading flag, and
// refetch runs the fetcher again.
function useApiStub<T>(fetcher: () => Promise<{ data: T }>) {
  const [state, setState] = React.useState<{ data?: T; isLoading: boolean; error: Error | null }>({
    isLoading: true,
    error: null,
  });
  const fetcherRef = React.useRef(fetcher);
  fetcherRef.current = fetcher;
  const refetch = React.useCallback(async () => {
    setState((s) => ({ ...s, isLoading: true, error: null }));
    try {
      const res = await fetcherRef.current();
      setState({ data: res.data, isLoading: false, error: null });
    } catch (err) {
      setState({ data: undefined, isLoading: false, error: err as Error });
    }
  }, []);
  React.useEffect(() => {
    void refetch();
  }, [refetch]);
  return { ...state, refetch };
}

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useInvitation: () => invitationHooks,
  useInvitationList: () => listResult,
  useIAM: () => iamResult,
  useApi: <T,>(fetcher: () => Promise<{ data: T }>) => useApiStub(fetcher),
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

describe("InvitationsPage invitation roles", () => {
  function openInvite() {
    fireEvent.click(screen.getByRole("button", { name: /^send invitation$/i }));
    return screen.getByRole("dialog");
  }

  it("offers the tenant's IAM role names from listRoles", async () => {
    listRoles.mockClear();
    render(<InvitationsPage />);
    await waitFor(() => expect(listRoles).toHaveBeenCalledWith({ tenantId: "tenant-1" }));

    const dialog = openInvite();
    const select = (await within(dialog).findByLabelText("Role")) as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(iamRoles);
    expect(select.value).toBe("user");
  });

  it("shows a failed role lookup with a retry, not an empty role list", async () => {
    listRoles.mockClear();
    listRoles.mockImplementationOnce(() => Promise.reject(new Error("roles unavailable")));
    render(<InvitationsPage />);
    await waitFor(() => expect(listRoles).toHaveBeenCalledTimes(1));

    const dialog = openInvite();
    expect(await within(dialog).findByText(/roles unavailable/)).toBeTruthy();
    expect(within(dialog).queryByText(/no IAM roles/i)).toBeNull();
    expect(within(dialog).queryByLabelText("Role")).toBeNull();
    fireEvent.change(within(dialog).getByLabelText("Email Address"), {
      target: { value: "r@example.com" },
    });
    const submit = within(dialog).getByRole("button", { name: /send invitation/i }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);

    fireEvent.click(within(dialog).getByRole("button", { name: "Retry" }));
    const select = (await within(dialog).findByLabelText("Role")) as HTMLSelectElement;
    expect(listRoles).toHaveBeenCalledTimes(2);
    expect(Array.from(select.options).map((o) => o.value)).toEqual(iamRoles);
    expect(within(dialog).queryByText(/roles unavailable/)).toBeNull();
    expect(submit.disabled).toBe(false);
  });
});
