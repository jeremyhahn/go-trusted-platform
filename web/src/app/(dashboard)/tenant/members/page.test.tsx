import * as React from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import MembersPage from "./page";
import type { Member, TenantRole } from "@/types/tenant";

// The page owns the data shaping (IAM users to Member rows), the empty,
// loading and error states, and the role/remove/invite handlers. The table
// and the invitation form are stubbed so the props the page hands them can be
// asserted, and the hooks are stubbed so each state can be forced.

type MutationOptions = {
  onSuccess?: () => void;
  onError?: (error: { message: string }) => void;
};
type Mutation = {
  fn: (vars: unknown) => unknown;
  opts: MutationOptions;
  mutate: ReturnType<typeof vi.fn>;
};

const state = {
  auth: { tenantId: "tenant-1" as string | null, isLoading: false },
  api: {
    data: null as { users?: unknown[] } | null,
    isLoading: false,
    error: null as { message: string } | null,
    refetch: vi.fn(),
  },
  apiCalls: [] as Array<{ fetcher: () => unknown; deps: unknown[]; opts: { enabled?: boolean } }>,
  mutations: [] as Mutation[],
};

const toast = vi.fn();
const iam = {
  listUsers: vi.fn(),
  assignRole: vi.fn(),
  deleteUser: vi.fn(),
};

type TableProps = {
  members: Member[];
  onRoleChange: (id: string, role: TenantRole) => Promise<void>;
  onRemove: (id: string) => Promise<void>;
  isLoading?: boolean;
};
type FormProps = { onSubmit: (data: unknown) => Promise<void> };
let tableProps: TableProps | null = null;
let formProps: FormProps | null = null;

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => state.auth,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast }),
  useIAM: () => iam,
  useApi: (fetcher: () => unknown, deps: unknown[], opts: { enabled?: boolean }) => {
    state.apiCalls.push({ fetcher, deps, opts });
    return state.api;
  },
  useMutation: (fn: (vars: unknown) => unknown, opts: MutationOptions) => {
    const m: Mutation = { fn, opts, mutate: vi.fn() };
    state.mutations.push(m);
    return { mutate: m.mutate };
  },
}));

vi.mock("@/components/features/tenant/member-table", () => ({
  MemberTable: (props: TableProps) => {
    tableProps = props;
    return (
      <ul data-testid="member-table">
        {props.members.map((m) => (
          <li key={m.id}>{`${m.user.name}|${m.user.email}|${m.role}`}</li>
        ))}
      </ul>
    );
  },
}));

vi.mock("@/components/features/tenant/invitation-form", () => ({
  InvitationForm: (props: FormProps & { trigger: React.ReactNode }) => {
    formProps = props;
    return <div>{props.trigger}</div>;
  },
}));

// The last render's two mutations: update role first, remove member second.
function lastMutations(): { updateRole: Mutation; remove: Mutation } {
  const n = state.mutations.length;
  return { updateRole: state.mutations[n - 2], remove: state.mutations[n - 1] };
}

beforeEach(() => {
  state.auth = { tenantId: "tenant-1", isLoading: false };
  state.api = { data: null, isLoading: false, error: null, refetch: vi.fn() };
  state.apiCalls = [];
  state.mutations = [];
  tableProps = null;
  formProps = null;
  toast.mockReset();
  iam.listUsers.mockReset();
  iam.assignRole.mockReset();
  iam.deleteUser.mockReset();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("MembersPage data", () => {
  it("maps IAM users to member rows, defaulting name to email and role to viewer", () => {
    state.api.data = {
      users: [
        { id: "u1", email: "alice-mail", name: "Alice", roles: ["admin", "member"], createdAt: "2026-01-01T00:00:00Z" },
        { id: "u2", email: "bob-mail", name: "", roles: [] },
        { id: "u3", email: "carol-mail" },
      ],
    };
    render(<MembersPage />);

    expect(screen.getByText("3 members in your tenant")).toBeTruthy();
    expect(tableProps).not.toBeNull();
    const members = tableProps!.members;
    expect(members.map((m) => `${m.user.name}|${m.role}`)).toEqual([
      "Alice|admin",
      "bob-mail|viewer",
      "carol-mail|viewer",
    ]);
    expect(members[0]).toMatchObject({
      id: "u1",
      userId: "u1",
      user: { id: "u1", email: "alice-mail", name: "Alice" },
      joinedAt: "2026-01-01T00:00:00Z",
    });
    // A missing createdAt falls back to a parseable timestamp.
    expect(Number.isNaN(Date.parse(members[2].joinedAt))).toBe(false);
    expect(tableProps!.isLoading).toBe(false);
  });

  it("uses the singular for a single member", () => {
    state.api.data = { users: [{ id: "u1", email: "solo-mail" }] };
    render(<MembersPage />);
    expect(screen.getByText("1 member in your tenant")).toBeTruthy();
  });

  it.each([
    ["no response", null],
    ["a response without users", {}],
    ["an empty user list", { users: [] }],
  ])("shows the empty state for %s", (_label, data) => {
    state.api.data = data as { users?: unknown[] } | null;
    render(<MembersPage />);
    expect(screen.getByText("No members yet")).toBeTruthy();
    expect(screen.getByText("0 members in your tenant")).toBeTruthy();
    expect(screen.queryByTestId("member-table")).toBeNull();
  });

  it.each([
    ["the list is loading", { api: true, auth: false }],
    ["auth is loading", { api: false, auth: true }],
  ])("shows skeletons and no table while %s", (_label, loading) => {
    state.api.isLoading = loading.api;
    state.auth.isLoading = loading.auth;
    state.api.data = { users: [{ id: "u1", email: "x" }] };
    render(<MembersPage />);
    expect(screen.queryByTestId("member-table")).toBeNull();
    expect(screen.queryByText(/in your tenant/)).toBeNull();
    expect(screen.queryByText("No members yet")).toBeNull();
  });

  it("asks for the tenant's users, enabled only with a tenant and auth settled", () => {
    render(<MembersPage />);
    const call = state.apiCalls[state.apiCalls.length - 1];
    expect(call.deps).toEqual(["tenant-1"]);
    expect(call.opts.enabled).toBe(true);
    void call.fetcher();
    expect(iam.listUsers).toHaveBeenCalledWith({ tenantId: "tenant-1", page: 1, pageSize: 100 });
  });

  it.each([
    ["no tenant", { tenantId: null, isLoading: false }],
    ["auth loading", { tenantId: "tenant-1", isLoading: true }],
  ])("disables the list query with %s", (_label, auth) => {
    state.auth = auth;
    render(<MembersPage />);
    expect(state.apiCalls[state.apiCalls.length - 1].opts.enabled).toBe(false);
  });

  it("passes an empty tenant id to the fetcher when there is no tenant", () => {
    state.auth = { tenantId: null, isLoading: false };
    render(<MembersPage />);
    void state.apiCalls[state.apiCalls.length - 1].fetcher();
    expect(iam.listUsers).toHaveBeenCalledWith({ tenantId: "", page: 1, pageSize: 100 });
  });
});

describe("MembersPage error state", () => {
  it("shows the error message and retries on click", () => {
    state.api.error = { message: "backend unavailable" };
    render(<MembersPage />);
    expect(screen.getByText("Error loading members")).toBeTruthy();
    expect(screen.getByText("backend unavailable")).toBeTruthy();
    expect(screen.queryByTestId("member-table")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(state.api.refetch).toHaveBeenCalledTimes(1);
  });
});

describe("MembersPage role change", () => {
  beforeEach(() => {
    state.api.data = { users: [{ id: "u1", email: "alice-mail" }] };
  });

  it("mutates with the member and role", async () => {
    render(<MembersPage />);
    await tableProps!.onRoleChange("u1", "admin" as TenantRole);
    expect(lastMutations().updateRole.mutate).toHaveBeenCalledWith({ userId: "u1", role: "admin" });
  });

  it("assigns the role in the current tenant", () => {
    render(<MembersPage />);
    void lastMutations().updateRole.fn({ userId: "u1", role: "admin" });
    expect(iam.assignRole).toHaveBeenCalledWith({ tenantId: "tenant-1", userId: "u1", roleId: "admin" });
  });

  it("toasts success and refetches", () => {
    render(<MembersPage />);
    lastMutations().updateRole.opts.onSuccess!();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Role updated", variant: "success" }));
    expect(state.api.refetch).toHaveBeenCalledTimes(1);
  });

  it("toasts the error message on failure without refetching", () => {
    render(<MembersPage />);
    lastMutations().updateRole.opts.onError!({ message: "forbidden" });
    expect(toast).toHaveBeenCalledWith({
      title: "Failed to update role",
      description: "forbidden",
      variant: "destructive",
    });
    expect(state.api.refetch).not.toHaveBeenCalled();
  });

});

describe("MembersPage without a tenant", () => {
  it("rejects role change and removal with no tenant context", async () => {
    state.auth = { tenantId: null, isLoading: false };
    state.api.data = { users: [{ id: "u1", email: "alice-mail" }] };
    render(<MembersPage />);
    await expect(tableProps!.onRoleChange("u1", "admin" as TenantRole)).rejects.toThrow("No tenant context");
    await expect(tableProps!.onRemove("u1")).rejects.toThrow("No tenant context");
    const { updateRole, remove } = lastMutations();
    expect(updateRole.mutate).not.toHaveBeenCalled();
    expect(remove.mutate).not.toHaveBeenCalled();
  });
});

describe("MembersPage removal", () => {
  beforeEach(() => {
    state.api.data = { users: [{ id: "u1", email: "alice-mail" }] };
  });

  it("mutates with the member id and deletes in the current tenant", async () => {
    render(<MembersPage />);
    await tableProps!.onRemove("u1");
    const { remove } = lastMutations();
    expect(remove.mutate).toHaveBeenCalledWith("u1");
    void remove.fn("u1");
    expect(iam.deleteUser).toHaveBeenCalledWith("tenant-1", "u1");
  });

  it("toasts success and refetches", () => {
    render(<MembersPage />);
    lastMutations().remove.opts.onSuccess!();
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Member removed", variant: "success" }));
    expect(state.api.refetch).toHaveBeenCalledTimes(1);
  });

  it("toasts the error message on failure", () => {
    render(<MembersPage />);
    lastMutations().remove.opts.onError!({ message: "not found" });
    expect(toast).toHaveBeenCalledWith({
      title: "Failed to remove member",
      description: "not found",
      variant: "destructive",
    });
  });
});

describe("MembersPage invitation", () => {
  it("renders the invite trigger", () => {
    render(<MembersPage />);
    expect(screen.getByRole("button", { name: /invite member/i })).toBeTruthy();
  });

  it("rejects a sent invitation as not yet available and toasts it", async () => {
    vi.spyOn(console, "log").mockImplementation(() => {});
    render(<MembersPage />);
    await expect(formProps!.onSubmit({ email: "invitee", role: "member" })).rejects.toThrow(
      "Invitation functionality not yet available",
    );
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Not available", variant: "destructive" }));
  });
});
