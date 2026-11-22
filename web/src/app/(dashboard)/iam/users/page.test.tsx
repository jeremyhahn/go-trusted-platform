import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import UsersPage from "./page";

type ApiOptions = { onError?: (err: Error) => void };
type MutationOptions = {
  onSuccess?: (result: unknown, variables: unknown) => void;
  onError?: (err: Error) => void;
};
type User = {
  id: string;
  name: string;
  email: string;
  status: string;
  roles: { id: string; name: string }[];
  createdAt: string;
  updatedAt: string;
  lastLoginAt?: string;
};
type Role = { id: string; name: string; description: string; permissions: { resource: string; action: string }[] };
type ApiResult = { data: unknown; isLoading: boolean; error: Error | null; refetch: () => void };

const push = vi.fn();
const toast = vi.fn();
const refetch = vi.fn();
const iam = {
  listUsers: vi.fn(),
  listRoles: vi.fn(),
  createUser: vi.fn(),
  deleteUser: vi.fn(),
  updateUser: vi.fn(),
};
const toastResult = { toast };
const authResult: { user: null; tenantId: string | undefined; isLoading: boolean } = {
  user: null,
  tenantId: "tenant-1",
  isLoading: false,
};
// Stable objects: a fresh `data` per render would re-run the page's memos.
const usersResult: ApiResult = { data: null, isLoading: false, error: null, refetch };
const rolesResult: ApiResult = { data: null, isLoading: false, error: null, refetch: vi.fn() };
const captured: {
  usersFetcher?: () => Promise<unknown>;
  usersOptions?: ApiOptions;
  rolesFetcher?: () => Promise<unknown>;
} = {};
const mutationState = { isLoading: false };
const tableProps: { users?: User[] } = {};
const formProps: { roles?: Role[] } = {};

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useIAM: () => iam,
  // The users query depends on the tenant only; the roles query also on
  // whether the form is open.
  useApi: (fetcher: () => Promise<unknown>, deps: unknown[], options?: ApiOptions) => {
    if (deps.length === 1) {
      captured.usersFetcher = fetcher;
      captured.usersOptions = options;
      return usersResult;
    }
    captured.rolesFetcher = fetcher;
    return rolesResult;
  },
  useMutation: (fn: (arg: unknown) => Promise<unknown>, options: MutationOptions) => {
    const mutateAsync = (arg: unknown) =>
      fn(arg).then(
        (result) => {
          options.onSuccess?.(result, arg);
          return result;
        },
        (err: Error) => {
          options.onError?.(err);
          throw err;
        },
      );
    return {
      isLoading: mutationState.isLoading,
      mutateAsync,
      mutate: (arg: unknown) => {
        mutateAsync(arg).catch(() => undefined);
      },
    };
  },
}));

vi.mock("@/components/features/iam/user-table", () => ({
  UserTable: (props: {
    users: User[];
    loading?: boolean;
    onView?: (u: User) => void;
    onEdit?: (u: User) => void;
    onDisable?: (u: User) => void;
    onDelete?: (u: User) => void;
    onBulkDelete?: (u: User[]) => void;
  }) => {
    tableProps.users = props.users;
    return (
      <div data-testid="table" data-loading={String(!!props.loading)}>
        {props.users.map((u) => (
          <div key={u.id} data-testid="row">
            <span>{u.name}</span>
            <button onClick={() => props.onView?.(u)}>View</button>
            <button onClick={() => props.onEdit?.(u)}>Edit</button>
            <button onClick={() => props.onDisable?.(u)}>Disable</button>
            <button onClick={() => props.onDelete?.(u)}>Delete</button>
          </div>
        ))}
        <button onClick={() => props.onBulkDelete?.(props.users)}>Delete selected</button>
      </div>
    );
  },
}));

const newUser = { email: "new-user", name: "New User", roleIds: ["role-admin"] };

vi.mock("@/components/features/iam/user-form", () => ({
  UserForm: (props: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
    onSubmit: (data: unknown) => void | Promise<void>;
    roles: Role[];
    loading?: boolean;
  }) => {
    formProps.roles = props.roles;
    if (!props.open) return null;
    return (
      <div data-testid="form" data-loading={String(!!props.loading)}>
        <button onClick={() => void Promise.resolve(props.onSubmit(newUser)).catch(() => undefined)}>
          Submit
        </button>
        <button onClick={() => props.onOpenChange(false)}>Close form</button>
      </div>
    );
  },
}));

const users = [
  {
    id: "user-alice",
    email: "alice-mail",
    name: "Alice",
    roles: ["admin", "viewer"],
    createdAt: "2026-11-01T00:00:00Z",
    updatedAt: "2026-11-02T00:00:00Z",
    lastAuth: "2026-11-03T00:00:00Z",
  },
  // No name, roles or timestamps: the email stands in for the name.
  { id: "user-bare", email: "bare-mail" },
];

const confirm = vi.spyOn(window, "confirm");

beforeEach(() => {
  vi.clearAllMocks();
  authResult.tenantId = "tenant-1";
  authResult.isLoading = false;
  usersResult.data = { users };
  usersResult.isLoading = false;
  usersResult.error = null;
  rolesResult.data = null;
  mutationState.isLoading = false;
  tableProps.users = undefined;
  formProps.roles = undefined;
  confirm.mockReturnValue(true);
});

afterEach(() => {
  cleanup();
});

function rowFor(text: string): HTMLElement {
  const row = screen.getByText(text).closest("[data-testid='row']");
  if (!row) throw new Error(`no table row for ${text}`);
  return row as HTMLElement;
}

function stat(title: string): string | null | undefined {
  return screen.getByText(title, { selector: "h3" }).parentElement?.parentElement?.textContent;
}

describe("UsersPage states", () => {
  it("shows the auth spinner while auth loads", () => {
    authResult.isLoading = true;
    render(<UsersPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("asks for a login when there is no tenant", () => {
    authResult.tenantId = undefined;
    render(<UsersPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("shows the load error and retries on request", () => {
    usersResult.error = new Error("backend down");
    render(<UsersPage />);
    expect(screen.getByText("Error Loading Users")).toBeTruthy();
    expect(screen.getByText("backend down")).toBeTruthy();
    fireEvent.click(screen.getByText("Retry"));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("passes the loading flag to the table", () => {
    usersResult.isLoading = true;
    render(<UsersPage />);
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
  });
});

describe("UsersPage fetching", () => {
  it("lists the tenant's users", async () => {
    iam.listUsers.mockResolvedValue({ success: true, data: { users: [] } });
    render(<UsersPage />);
    await captured.usersFetcher?.();
    expect(iam.listUsers).toHaveBeenCalledWith({ tenantId: "tenant-1" });
  });

  it("does not call the backend without a tenant", async () => {
    authResult.tenantId = undefined;
    render(<UsersPage />);
    await expect(captured.usersFetcher?.()).resolves.toEqual({ success: true, data: null });
    await expect(captured.rolesFetcher?.()).resolves.toEqual({ success: true, data: null });
    expect(iam.listUsers).not.toHaveBeenCalled();
    expect(iam.listRoles).not.toHaveBeenCalled();
  });

  it("toasts a load error", () => {
    render(<UsersPage />);
    captured.usersOptions?.onError?.(new Error("timeout"));
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading users",
      description: "timeout",
      variant: "destructive",
    });
  });

  it("fetches roles only while the form is open", async () => {
    iam.listRoles.mockResolvedValue({ success: true, data: { roles: [] } });
    render(<UsersPage />);
    await expect(captured.rolesFetcher?.()).resolves.toEqual({ success: true, data: null });
    expect(iam.listRoles).not.toHaveBeenCalled();

    fireEvent.click(screen.getByText("Add User"));
    await captured.rolesFetcher?.();
    expect(iam.listRoles).toHaveBeenCalledWith({ tenantId: "tenant-1" });
  });
});

describe("UsersPage rendering", () => {
  it("maps each user with fallbacks", () => {
    render(<UsersPage />);
    expect(screen.getAllByTestId("row")).toHaveLength(2);
    expect(rowFor("Alice")).toBeTruthy();
    expect(rowFor("bare-mail")).toBeTruthy();

    const [alice, bare] = tableProps.users ?? [];
    expect(alice).toMatchObject({
      id: "user-alice",
      email: "alice-mail",
      name: "Alice",
      status: "active",
      createdAt: "2026-11-01T00:00:00Z",
      updatedAt: "2026-11-02T00:00:00Z",
      lastLoginAt: "2026-11-03T00:00:00Z",
      permissions: [],
    });
    expect(alice.roles.map((r) => r.id)).toEqual(["admin", "viewer"]);
    expect(alice.roles[0]).toMatchObject({ id: "admin", name: "admin", userCount: 0 });

    expect(bare.name).toBe("bare-mail");
    expect(bare.roles).toEqual([]);
    expect(bare.lastLoginAt).toBeUndefined();
    // Missing timestamps fall back to a valid current time.
    expect(Number.isNaN(Date.parse(bare.createdAt))).toBe(false);
    expect(Number.isNaN(Date.parse(bare.updatedAt))).toBe(false);
  });

  it("totals all, active and pending users", () => {
    render(<UsersPage />);
    expect(stat("Total Users")).toBe("Total Users2");
    expect(stat("Active Users")).toBe("Active Users2");
    expect(stat("Pending Users")).toBe("Pending Users0");
  });

  it.each([
    ["no data", null],
    ["no users field", {}],
    ["an empty list", { users: [] }],
  ])("shows an empty table for %s", (_name, data) => {
    usersResult.data = data;
    render(<UsersPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Users")).toBe("Total Users0");
    expect(stat("Active Users")).toBe("Active Users0");
  });

  it("maps the roles handed to the form", () => {
    rolesResult.data = {
      roles: [
        { id: "role-admin", name: "admin", description: "Admins", permissions: ["users:read", "audit"] },
        { id: "role-bare" },
      ],
    };
    render(<UsersPage />);
    const [admin, bare] = formProps.roles ?? [];
    expect(admin).toMatchObject({ id: "role-admin", name: "admin", description: "Admins" });
    expect(admin.permissions).toMatchObject([
      { resource: "users", action: "read" },
      { resource: "audit", action: "*" },
    ]);
    expect(bare).toMatchObject({ id: "role-bare", name: "role-bare", description: "", permissions: [] });
  });

  it("hands the form no roles when none are loaded", () => {
    rolesResult.data = { roles: undefined };
    render(<UsersPage />);
    expect(formProps.roles).toEqual([]);
  });
});

describe("UsersPage navigation", () => {
  it("opens a user from View and Edit", () => {
    render(<UsersPage />);
    const row = rowFor("Alice");
    fireEvent.click(within(row).getByText("View"));
    fireEvent.click(within(row).getByText("Edit"));
    expect(push.mock.calls).toEqual([["/iam/users/user-alice"], ["/iam/users/user-alice"]]);
  });
});

describe("UsersPage create", () => {
  it("opens and closes the form", () => {
    render(<UsersPage />);
    expect(screen.queryByTestId("form")).toBeNull();
    fireEvent.click(screen.getByText("Add User"));
    expect(screen.getByTestId("form")).toBeTruthy();
    fireEvent.click(screen.getByText("Close form"));
    expect(screen.queryByTestId("form")).toBeNull();
  });

  it("creates the user, refetches and closes the form", async () => {
    iam.createUser.mockResolvedValue({ success: true });
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Add User"));
    fireEvent.click(screen.getByText("Submit"));
    expect(iam.createUser).toHaveBeenCalledWith({
      tenantId: "tenant-1",
      email: "new-user",
      name: "New User",
      roles: ["role-admin"],
    });
    await waitFor(() => expect(screen.queryByTestId("form")).toBeNull());
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "User created", variant: "success" }),
    );
  });

  it("toasts a failed create and keeps the form open", async () => {
    iam.createUser.mockRejectedValue(new Error("exists"));
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Add User"));
    fireEvent.click(screen.getByText("Submit"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error creating user",
        description: "exists",
        variant: "destructive",
      }),
    );
    expect(screen.getByTestId("form")).toBeTruthy();
    expect(refetch).not.toHaveBeenCalled();
  });

  it("passes the create loading flag to the form", () => {
    mutationState.isLoading = true;
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Add User"));
    expect(screen.getByTestId("form").getAttribute("data-loading")).toBe("true");
  });
});

describe("UsersPage disable", () => {
  it("updates an active user and reports it disabled", async () => {
    iam.updateUser.mockResolvedValue({ success: true });
    render(<UsersPage />);
    fireEvent.click(within(rowFor("Alice")).getByText("Disable"));
    expect(iam.updateUser).toHaveBeenCalledWith({
      tenantId: "tenant-1",
      userId: "user-alice",
      name: "Alice",
    });
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "User disabled",
        description: "The user has been disabled successfully",
        variant: "success",
      }),
    );
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("toasts a failed update", async () => {
    iam.updateUser.mockRejectedValue(new Error("denied"));
    render(<UsersPage />);
    fireEvent.click(within(rowFor("Alice")).getByText("Disable"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error updating user",
        description: "denied",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});

describe("UsersPage delete", () => {
  it("deletes a confirmed user and refetches", async () => {
    iam.deleteUser.mockResolvedValue({ success: true });
    render(<UsersPage />);
    fireEvent.click(within(rowFor("Alice")).getByText("Delete"));
    expect(confirm).toHaveBeenCalledWith("Are you sure you want to delete Alice?");
    expect(iam.deleteUser).toHaveBeenCalledWith("tenant-1", "user-alice");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "User deleted", variant: "success" }),
    );
  });

  it("keeps the user when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<UsersPage />);
    fireEvent.click(within(rowFor("Alice")).getByText("Delete"));
    expect(iam.deleteUser).not.toHaveBeenCalled();
  });

  it("toasts a failed delete without refetching", async () => {
    iam.deleteUser.mockRejectedValue(new Error("forbidden"));
    render(<UsersPage />);
    fireEvent.click(within(rowFor("bare-mail")).getByText("Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting user",
        description: "forbidden",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});

describe("UsersPage bulk delete", () => {
  it("deletes every selected user", async () => {
    iam.deleteUser.mockResolvedValue({ success: true });
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(confirm).toHaveBeenCalledWith("Are you sure you want to delete 2 user(s)?");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(iam.deleteUser.mock.calls).toEqual([
      ["tenant-1", "user-alice"],
      ["tenant-1", "user-bare"],
    ]);
    expect(toast).toHaveBeenCalledWith({
      title: "Users deleted",
      description: "2 user(s) have been deleted successfully",
      variant: "success",
    });
  });

  it("does nothing when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(iam.deleteUser).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });

  it("reports a partial failure", async () => {
    iam.deleteUser.mockResolvedValueOnce({ success: true }).mockRejectedValueOnce(new Error("no"));
    render(<UsersPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting users",
        description: "Some users could not be deleted",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});
