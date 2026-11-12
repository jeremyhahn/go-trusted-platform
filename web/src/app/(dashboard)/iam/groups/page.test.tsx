import * as React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

type MutationOpts = {
  onSuccess?: (data: unknown) => void;
  onError?: (err: Error) => void;
};
type ApiOpts = { onError?: (err: Error) => void };
type Cell = (ctx: { row: { original: unknown } }) => React.ReactNode;
type Action = { label: string; onClick: () => void };
type Bulk = { label: string; onClick: (rows: unknown[]) => void };

const push = vi.fn();
const toast = vi.fn();
const refetch = vi.fn();
const listGroups = vi.fn();
const deleteGroup = vi.fn();
const auth = { user: null, tenantId: "t1" as string | null, isLoading: false };
const api: { data: unknown; isLoading: boolean; error: Error | null } = {
  data: null,
  isLoading: false,
  error: null,
};
const captured: { fetcher?: () => unknown; opts?: ApiOpts } = {};

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));
vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => auth }));
vi.mock("@/hooks", () => ({
  useIAM: () => ({ listGroups, deleteGroup }),
  useToast: () => ({ toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], opts: ApiOpts) => {
    captured.fetcher = fetcher;
    captured.opts = opts;
    return { ...api, refetch };
  },
  useMutation: (fn: (v: string) => Promise<unknown>, opts: MutationOpts) => ({
    isLoading: false,
    mutate: async (v: string) => {
      try {
        opts.onSuccess?.(await fn(v));
      } catch (err) {
        opts.onError?.(err as Error);
      }
    },
  }),
}));
vi.mock("@/components/ui/data-table", () => ({
  createSelectColumn: () => ({ id: "select" }),
  DataTable: (props: {
    columns: Array<{ id?: string; cell?: Cell }>;
    data: unknown[];
    loading?: boolean;
    onRowClick?: (row: unknown) => void;
    bulkActions?: Bulk[];
  }) => (
    <div data-testid="table" data-loading={String(Boolean(props.loading))}>
      {props.data.map((row, i) => (
        <div key={i} data-testid="row">
          <button onClick={() => props.onRowClick?.(row)}>open</button>
          {props.columns.map((c, j) =>
            c.cell && c.id !== "select" ? <div key={j}>{c.cell({ row: { original: row } })}</div> : null,
          )}
        </div>
      ))}
      {props.bulkActions?.map((a) => (
        <button key={a.label} onClick={() => a.onClick(props.data)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));
vi.mock("@/components/ui/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));
vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({ actions }: { actions: Action[] }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} onClick={a.onClick}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

import GroupsPage from "./page";

const groups = [
  { id: "eng", name: "Engineering", description: "builders", members: ["a", "b", "c"] },
  { id: "ops", name: "", description: "", members: [] },
  { id: "sec" },
];

const rows = () => screen.getAllByTestId("row");
const stat = (title: string) =>
  screen.getByText(title).closest("div")!.parentElement!.textContent;

let confirmSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  for (const f of [push, toast, refetch, listGroups, deleteGroup]) f.mockReset();
  auth.tenantId = "t1";
  auth.isLoading = false;
  api.data = { groups };
  api.isLoading = false;
  api.error = null;
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
});
afterEach(() => {
  cleanup();
  confirmSpy.mockRestore();
});

describe("GroupsPage", () => {
  it("shows the auth loading state", () => {
    auth.isLoading = true;
    render(<GroupsPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("asks to log in again when there is no tenant", () => {
    auth.tenantId = null;
    render(<GroupsPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("the fetcher lists the tenant's groups, and resolves empty without a tenant", async () => {
    listGroups.mockResolvedValue({ groups: [] });
    render(<GroupsPage />);
    await captured.fetcher!();
    expect(listGroups).toHaveBeenCalledWith({ tenantId: "t1" });
    cleanup();
    auth.tenantId = null;
    render(<GroupsPage />);
    await expect(captured.fetcher!()).resolves.toEqual({ success: true, data: null });
    expect(listGroups).toHaveBeenCalledTimes(1);
  });

  it("the fetch error handler toasts the message", () => {
    render(<GroupsPage />);
    captured.opts!.onError!(new Error("down"));
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading groups",
      description: "down",
      variant: "destructive",
    });
  });

  it("shows a load error with a working Retry", () => {
    api.error = new Error("network unreachable");
    render(<GroupsPage />);
    expect(screen.getByText("Error Loading Groups")).toBeTruthy();
    expect(screen.getByText(/network unreachable/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("renders zero stats and no rows for missing data or a missing list", () => {
    api.data = null;
    render(<GroupsPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Groups")).toContain("0");
    cleanup();
    api.data = {};
    render(<GroupsPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Members")).toContain("0");
    expect(stat("Empty Groups")).toContain("0");
  });

  it("passes the loading flag to the table", () => {
    api.isLoading = true;
    render(<GroupsPage />);
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
  });

  it("computes the stats from the groups", () => {
    render(<GroupsPage />);
    expect(stat("Total Groups")).toContain("3");
    expect(stat("Total Members")).toContain("3");
    expect(stat("Empty Groups")).toContain("2");
  });

  it("falls back to the id for the name and a dash for the description", () => {
    render(<GroupsPage />);
    const first = within(rows()[0]);
    expect(first.getByText("Engineering")).toBeTruthy();
    expect(first.getByText("builders")).toBeTruthy();
    expect(first.getByText("3")).toBeTruthy();
    const second = within(rows()[1]);
    expect(second.getByText("ops")).toBeTruthy();
    expect(second.getByText("-")).toBeTruthy();
    expect(second.getByText("0")).toBeTruthy();
    expect(within(rows()[2]).getByText("sec")).toBeTruthy();
  });

  it("navigates to the new-group form, and to the group on view, edit and row click", () => {
    render(<GroupsPage />);
    fireEvent.click(screen.getByRole("button", { name: /Add Group/ }));
    expect(push).toHaveBeenLastCalledWith("/iam/groups/new");
    const r = within(rows()[1]);
    for (const name of ["View", "Edit", "open"]) {
      push.mockReset();
      fireEvent.click(r.getByRole("button", { name }));
      expect(push).toHaveBeenCalledWith("/iam/groups/ops");
    }
  });

  it("deletes a confirmed group and refetches", async () => {
    deleteGroup.mockResolvedValue({});
    render(<GroupsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    expect(confirmSpy).toHaveBeenCalledWith("Are you sure you want to delete Engineering?");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(deleteGroup).toHaveBeenCalledWith("t1", "eng");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Group deleted" }));
  });

  it("does nothing when the delete is not confirmed", () => {
    confirmSpy.mockReturnValue(false);
    render(<GroupsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    expect(deleteGroup).not.toHaveBeenCalled();
  });

  it("toasts a failed delete and does not refetch", async () => {
    deleteGroup.mockRejectedValue(new Error("forbidden"));
    render(<GroupsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting group",
        description: "forbidden",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });

  it("bulk deletes every selected group", async () => {
    deleteGroup.mockResolvedValue({});
    render(<GroupsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(confirmSpy).toHaveBeenCalledWith("Are you sure you want to delete 3 group(s)?");
    expect(deleteGroup).toHaveBeenCalledTimes(3);
    expect(deleteGroup).toHaveBeenCalledWith("t1", "sec");
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: "3 group(s) have been deleted successfully" }),
    );
  });

  it("bulk delete reports a partial failure", async () => {
    deleteGroup.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error("x")).mockResolvedValue({});
    render(<GroupsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Error deleting groups" })),
    );
    expect(refetch).not.toHaveBeenCalled();
  });

  it("bulk delete does nothing when not confirmed", () => {
    confirmSpy.mockReturnValue(false);
    render(<GroupsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    expect(deleteGroup).not.toHaveBeenCalled();
  });
});
