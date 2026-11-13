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
const listApps = vi.fn();
const deleteApp = vi.fn();
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
  useIAM: () => ({ listApps, deleteApp }),
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

import AppsPage from "./page";

const apps = [
  {
    clientId: "client-0123456789abcdef",
    name: "Billing",
    redirectUris: ["a/cb", "b/cb"],
    grantTypes: ["client_credentials", "authorization_code", "refresh_token"],
  },
  { clientId: "short-id", name: "", redirectUris: [], grantTypes: [] },
  {},
];

const rows = () => screen.getAllByTestId("row");
const stat = (title: string) =>
  screen.getByText(title).closest("div")!.parentElement!.textContent;

const confirmSpy = vi.fn<(message?: string) => boolean>();

beforeEach(() => {
  for (const f of [push, toast, refetch, listApps, deleteApp]) f.mockReset();
  auth.tenantId = "t1";
  auth.isLoading = false;
  api.data = { apps };
  api.isLoading = false;
  api.error = null;
  confirmSpy.mockReset();
  confirmSpy.mockReturnValue(true);
  vi.stubGlobal("confirm", confirmSpy);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("AppsPage", () => {
  it("shows the auth loading state", () => {
    auth.isLoading = true;
    render(<AppsPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("asks to log in again when there is no tenant", () => {
    auth.tenantId = null;
    render(<AppsPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("the fetcher lists the tenant's apps, and resolves empty without a tenant", async () => {
    listApps.mockResolvedValue({ apps: [] });
    render(<AppsPage />);
    await captured.fetcher!();
    expect(listApps).toHaveBeenCalledWith({ tenantId: "t1" });
    cleanup();
    auth.tenantId = null;
    render(<AppsPage />);
    await expect(captured.fetcher!()).resolves.toEqual({ success: true, data: null });
    expect(listApps).toHaveBeenCalledTimes(1);
  });

  it("the fetch error handler toasts the message", () => {
    render(<AppsPage />);
    captured.opts!.onError!(new Error("down"));
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading applications",
      description: "down",
      variant: "destructive",
    });
  });

  it("shows a load error with a working Retry", () => {
    api.error = new Error("network unreachable");
    render(<AppsPage />);
    expect(screen.getByText("Error Loading Applications")).toBeTruthy();
    expect(screen.getByText(/network unreachable/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("renders zero stats and no rows for missing data", () => {
    api.data = null;
    render(<AppsPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Applications")).toContain("0");
    expect(stat("With Redirect URIs")).toContain("0");
    expect(stat("Total Redirect URIs")).toContain("0");
  });

  it("passes the loading flag to the table", () => {
    api.isLoading = true;
    render(<AppsPage />);
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
  });

  it("computes the stats from the apps", () => {
    render(<AppsPage />);
    expect(stat("Total Applications")).toContain("3");
    expect(stat("With Redirect URIs")).toContain("1");
    expect(stat("Total Redirect URIs")).toContain("2");
  });

  it("falls back to the client id, then 'unnamed', for the name", () => {
    render(<AppsPage />);
    expect(within(rows()[0]).getByText("Billing")).toBeTruthy();
    expect(within(rows()[1]).getAllByText("short-id").length).toBeGreaterThan(0);
    expect(within(rows()[2]).getByText("unnamed")).toBeTruthy();
  });

  it("truncates long client ids and shows a dash for none", () => {
    render(<AppsPage />);
    expect(within(rows()[0]).getByText("client-012345678...")).toBeTruthy();
    expect(within(rows()[2]).getAllByText("—").length).toBe(2);
  });

  it("shows two grant badges plus an overflow count", () => {
    render(<AppsPage />);
    const r = within(rows()[0]);
    expect(r.getByText("client credentials")).toBeTruthy();
    expect(r.getByText("authorization code")).toBeTruthy();
    expect(r.queryByText("refresh token")).toBeNull();
    expect(r.getByText("+1")).toBeTruthy();
  });

  it("navigates to the new-app form, and to the app on view, edit and row click", () => {
    render(<AppsPage />);
    fireEvent.click(screen.getByRole("button", { name: /Register Application/ }));
    expect(push).toHaveBeenLastCalledWith("/iam/apps/new");
    const r = within(rows()[1]);
    for (const name of ["View", "Edit", "open"]) {
      push.mockReset();
      fireEvent.click(r.getByRole("button", { name }));
      expect(push).toHaveBeenCalledWith("/iam/apps/short-id");
    }
  });

  it("Rotate Secret only announces the feature", () => {
    render(<AppsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Rotate Secret" }));
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Feature coming soon" }));
    expect(deleteApp).not.toHaveBeenCalled();
  });

  it("deletes a confirmed app and refetches", async () => {
    deleteApp.mockResolvedValue({});
    render(<AppsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    expect(confirmSpy).toHaveBeenCalledWith('Are you sure you want to delete "Billing"?');
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(deleteApp).toHaveBeenCalledWith("t1", "client-0123456789abcdef");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Application deleted" }));
  });

  it("does nothing when the delete is not confirmed", () => {
    confirmSpy.mockReturnValue(false);
    render(<AppsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    expect(deleteApp).not.toHaveBeenCalled();
  });

  it("toasts a failed delete and does not refetch", async () => {
    deleteApp.mockRejectedValue(new Error("forbidden"));
    render(<AppsPage />);
    fireEvent.click(within(rows()[0]).getByRole("button", { name: "Delete" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting application",
        description: "forbidden",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });

  it("bulk deletes every selected app", async () => {
    deleteApp.mockResolvedValue({});
    render(<AppsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(confirmSpy).toHaveBeenCalledWith("Are you sure you want to delete 3 application(s)?");
    expect(deleteApp).toHaveBeenCalledTimes(3);
    expect(deleteApp).toHaveBeenCalledWith("t1", "short-id");
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ description: "3 application(s) have been deleted successfully" }),
    );
  });

  it("bulk delete reports a partial failure", async () => {
    deleteApp.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error("x")).mockResolvedValue({});
    render(<AppsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting applications" }),
      ),
    );
    expect(refetch).not.toHaveBeenCalled();
  });

  it("bulk delete does nothing when not confirmed", () => {
    confirmSpy.mockReturnValue(false);
    render(<AppsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Delete selected" }));
    expect(deleteApp).not.toHaveBeenCalled();
  });
});
