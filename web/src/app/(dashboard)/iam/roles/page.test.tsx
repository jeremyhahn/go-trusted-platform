import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import RolesPage from "./page";

type Row = Record<string, unknown>;
type Col = {
  id?: string;
  accessorKey?: string;
  header?: unknown;
  cell?: (ctx: { row: { original: Row } }) => React.ReactNode;
};
type BulkAction = { label: string; onClick: (rows: Row[]) => unknown };
type ApiOptions = { onError?: (err: Error) => void };
type MutationOptions = {
  onSuccess?: (result: unknown) => void;
  onError?: (err: Error) => void;
};

const push = vi.fn();
const toast = vi.fn();
const refetch = vi.fn();
const iam = { listRoles: vi.fn(), deleteRole: vi.fn() };
const toastResult = { toast };
const authResult: { user: null; tenantId: string | undefined; isLoading: boolean } = {
  user: null,
  tenantId: "tenant-1",
  isLoading: false,
};
// A stable object: a fresh `data` per render would re-run the page's memo.
const apiResult: { data: unknown; isLoading: boolean; error: Error | null; refetch: typeof refetch } = {
  data: null,
  isLoading: false,
  error: null,
  refetch,
};
const captured: { fetcher?: () => Promise<unknown>; options?: ApiOptions } = {};

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => toastResult,
  useIAM: () => iam,
  useApi: (fetcher: () => Promise<unknown>, _deps: unknown[], options: ApiOptions) => {
    captured.fetcher = fetcher;
    captured.options = options;
    return apiResult;
  },
  useMutation: (fn: (arg: unknown) => Promise<unknown>, options: MutationOptions) => ({
    isLoading: false,
    mutate: (arg: unknown) => {
      void fn(arg).then(
        (result) => options.onSuccess?.(result),
        (err: Error) => options.onError?.(err),
      );
    },
  }),
}));

// The real table needs tanstack state; this one renders the page's own
// column cells and hands its row click and bulk actions to buttons.
vi.mock("@/components/ui/data-table", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/ui/data-table")>()),
  DataTable: ({
    columns,
    data,
    loading,
    onRowClick,
    bulkActions,
  }: {
    columns: Col[];
    data: Row[];
    loading?: boolean;
    onRowClick?: (row: Row) => void;
    bulkActions?: BulkAction[];
  }) => {
    const shown = columns.filter((c) => c.accessorKey || c.id === "actions");
    return (
      <div data-testid="table" data-loading={String(!!loading)}>
        {shown.map((c, i) => (
          <div key={`h${i}`} data-testid="header">
            {typeof c.header === "function"
              ? (c.header as (ctx: { column: object }) => React.ReactNode)({ column: {} })
              : (c.header as React.ReactNode)}
          </div>
        ))}
        {data.map((r, i) => (
          <div key={i} data-testid="row">
            {shown.map((c, j) => (
              <div key={j}>{c.cell?.({ row: { original: r } })}</div>
            ))}
            <button onClick={() => onRowClick?.(r)}>open row</button>
          </div>
        ))}
        {bulkActions?.map((a) => (
          <button key={a.label} onClick={() => void a.onClick(data)}>
            {a.label}
          </button>
        ))}
      </div>
    );
  },
}));

vi.mock("@/components/ui/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({ actions }: { actions: { label: string; onClick: () => void }[] }) => (
    <>
      {actions.map((a) => (
        <button key={a.label} onClick={a.onClick}>
          {a.label}
        </button>
      ))}
    </>
  ),
}));

const roles = [
  {
    id: "role-admin",
    name: "admin",
    description: "Administrators",
    permissions: ["users:read", "users:write"],
    createdAt: "2026-11-01T00:00:00Z",
    updatedAt: "2026-11-02T00:00:00Z",
  },
  // No name, description or permissions: the id stands in for the name.
  { id: "role-bare" },
  { id: "role-audit", name: "auditor", permissions: ["audit"] },
];

const confirm = vi.spyOn(window, "confirm");

beforeEach(() => {
  vi.clearAllMocks();
  authResult.tenantId = "tenant-1";
  authResult.isLoading = false;
  apiResult.data = { roles };
  apiResult.isLoading = false;
  apiResult.error = null;
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
  return screen.getByText(title).parentElement?.parentElement?.textContent;
}

describe("RolesPage states", () => {
  it("shows the auth spinner while auth loads", () => {
    authResult.isLoading = true;
    render(<RolesPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("asks for a login when there is no tenant", () => {
    authResult.tenantId = undefined;
    render(<RolesPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("shows the load error and retries on request", () => {
    apiResult.error = new Error("backend down");
    render(<RolesPage />);
    expect(screen.getByText("Error Loading Roles")).toBeTruthy();
    expect(screen.getByText("backend down")).toBeTruthy();
    fireEvent.click(screen.getByText("Retry"));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("passes the loading flag to the table", () => {
    apiResult.isLoading = true;
    render(<RolesPage />);
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
  });
});

describe("RolesPage fetching", () => {
  it("lists the tenant's roles", async () => {
    iam.listRoles.mockResolvedValue({ success: true, data: { roles: [] } });
    render(<RolesPage />);
    await captured.fetcher?.();
    expect(iam.listRoles).toHaveBeenCalledWith({ tenantId: "tenant-1" });
  });

  it("does not call the backend without a tenant", async () => {
    authResult.tenantId = undefined;
    render(<RolesPage />);
    await expect(captured.fetcher?.()).resolves.toEqual({ success: true, data: null });
    expect(iam.listRoles).not.toHaveBeenCalled();
  });

  it("toasts a load error", () => {
    render(<RolesPage />);
    captured.options?.onError?.(new Error("timeout"));
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading roles",
      description: "timeout",
      variant: "destructive",
    });
  });
});

describe("RolesPage rendering", () => {
  it("maps each role to a row with fallbacks", () => {
    render(<RolesPage />);
    expect(screen.getAllByTestId("row")).toHaveLength(3);

    const admin = rowFor("admin");
    expect(within(admin).getByText("Administrators")).toBeTruthy();
    expect(within(admin).getByText("2")).toBeTruthy();

    const bare = rowFor("role-bare");
    expect(within(bare).getByText("-")).toBeTruthy();
    expect(within(bare).getAllByText("0")).toHaveLength(2);

    expect(within(rowFor("auditor")).getByText("1")).toBeTruthy();
  });

  it("renders the column headers", () => {
    render(<RolesPage />);
    const headers = screen.getAllByTestId("header").map((h) => h.textContent);
    expect(headers).toEqual(["Role Name", "Description", "Users", "Permissions", ""]);
  });

  it("totals the roles, users and permissions", () => {
    render(<RolesPage />);
    expect(stat("Total Roles")).toBe("Total Roles3");
    expect(stat("Total Users")).toBe("Total Users0");
    expect(stat("Total Permissions")).toBe("Total Permissions3");
  });

  it.each([
    ["no data", null],
    ["no roles field", {}],
    ["an empty list", { roles: [] }],
  ])("shows an empty table for %s", (_name, data) => {
    apiResult.data = data;
    render(<RolesPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Roles")).toBe("Total Roles0");
    expect(stat("Total Permissions")).toBe("Total Permissions0");
  });
});

describe("RolesPage navigation", () => {
  it("opens a role from View, Edit and a row click", () => {
    render(<RolesPage />);
    const row = rowFor("admin");
    fireEvent.click(within(row).getByText("View"));
    fireEvent.click(within(row).getByText("Edit"));
    fireEvent.click(within(row).getByText("open row"));
    expect(push.mock.calls).toEqual([
      ["/iam/roles/role-admin"],
      ["/iam/roles/role-admin"],
      ["/iam/roles/role-admin"],
    ]);
  });

  it("goes to the new role form", () => {
    render(<RolesPage />);
    fireEvent.click(screen.getByText("Add Role"));
    expect(push).toHaveBeenCalledWith("/iam/roles/new");
  });
});

describe("RolesPage delete", () => {
  it("deletes a confirmed role and refetches", async () => {
    iam.deleteRole.mockResolvedValue({ success: true });
    render(<RolesPage />);
    fireEvent.click(within(rowFor("admin")).getByText("Delete"));
    expect(confirm).toHaveBeenCalledWith("Are you sure you want to delete admin?");
    expect(iam.deleteRole).toHaveBeenCalledWith("tenant-1", "role-admin");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Role deleted", variant: "success" }),
    );
  });

  it("keeps the role when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<RolesPage />);
    fireEvent.click(within(rowFor("admin")).getByText("Delete"));
    expect(iam.deleteRole).not.toHaveBeenCalled();
  });

  it("toasts a failed delete without refetching", async () => {
    iam.deleteRole.mockRejectedValue(new Error("forbidden"));
    render(<RolesPage />);
    fireEvent.click(within(rowFor("auditor")).getByText("Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting role",
        description: "forbidden",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});

describe("RolesPage bulk delete", () => {
  it("deletes every selected role", async () => {
    iam.deleteRole.mockResolvedValue({ success: true });
    render(<RolesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(confirm).toHaveBeenCalledWith("Are you sure you want to delete 3 role(s)?");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(iam.deleteRole.mock.calls).toEqual([
      ["tenant-1", "role-admin"],
      ["tenant-1", "role-bare"],
      ["tenant-1", "role-audit"],
    ]);
    expect(toast).toHaveBeenCalledWith({
      title: "Roles deleted",
      description: "3 role(s) have been deleted successfully",
      variant: "success",
    });
  });

  it("does nothing when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<RolesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(iam.deleteRole).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });

  it("reports a partial failure", async () => {
    iam.deleteRole.mockResolvedValueOnce({ success: true }).mockRejectedValueOnce(new Error("no"));
    render(<RolesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting roles",
        description: "Some roles could not be deleted",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});
