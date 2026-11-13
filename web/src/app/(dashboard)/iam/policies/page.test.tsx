/* eslint-disable @typescript-eslint/no-explicit-any */
import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

import PoliciesPage from "./page";

// Hooks are mocked at the module boundary: useApi records its fetcher and
// options and returns a stable result; useMutation records its function and
// options and runs them the way the real hook does (onSuccess or onError).
const router = { push: vi.fn() };
const toast = vi.fn();
const iam = { listPolicies: vi.fn(), deletePolicy: vi.fn() };
const refetch = vi.fn();

let authResult: { tenantId?: string; isLoading: boolean };
let listResult: { data: unknown; isLoading: boolean; error: Error | null; refetch: () => void };
let apiCall: { fn: () => Promise<unknown>; opts: any };
let mutationCall: { fn: (v: string) => Promise<unknown>; opts: any };

const mutation = {
  isLoading: false,
  mutate: vi.fn(async (v: string) => {
    try {
      const r = await mutationCall.fn(v);
      mutationCall.opts?.onSuccess?.(r, v);
    } catch (e) {
      mutationCall.opts?.onError?.(e, v);
    }
  }),
};

const policiesData = {
  policies: [
    { name: "p/high", description: "Urgent", priority: 5, labels: { a: "1", b: "2" } },
    { name: "mid", description: "", priority: 50 },
    { name: "low", description: "Low", priority: 500, labels: {} },
  ],
};

vi.mock("next/navigation", () => ({ useRouter: () => router }));

vi.mock("@/contexts/AuthContext", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/contexts/AuthContext")>()),
  useAuth: () => authResult,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useToast: () => ({ toast }),
  useApi: (fn: () => Promise<unknown>, _deps: unknown[], opts: unknown) => {
    apiCall = { fn, opts };
    return listResult;
  },
  useMutation: (fn: (v: string) => Promise<unknown>, opts: unknown) => {
    mutationCall = { fn, opts };
    return mutation;
  },
}));

// The real table needs a full tanstack instance; this one renders each row's
// cells from the page's own column definitions (the select column aside),
// a row-click button, and the page's bulk actions applied to every row.
vi.mock("@/components/ui/data-table", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/ui/data-table")>()),
  DataTable: ({ columns, data, onRowClick, bulkActions, loading }: any) => (
    <div data-testid="table" data-loading={String(loading)}>
      {data.map((row: any) => (
        <div key={row.name} data-testid={`row-${row.name}`}>
          <button type="button" onClick={() => onRowClick?.(row)}>
            open {row.name}
          </button>
          {columns
            .filter((c: any) => c.id !== "select")
            .map((c: any, i: number) => (
              <div key={i}>{typeof c.cell === "function" ? c.cell({ row: { original: row } }) : null}</div>
            ))}
        </div>
      ))}
      {bulkActions?.map((a: any) => (
        <button key={a.label} type="button" onClick={() => a.onClick(data)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({ actions }: any) => (
    <>
      {actions.map((a: any) => (
        <button key={a.label} type="button" onClick={a.onClick}>
          {a.label}
        </button>
      ))}
    </>
  ),
}));

const statCard = (title: string) =>
  screen.getByText(title).parentElement?.parentElement?.textContent;

let confirmSpy: MockInstance<(message?: string) => boolean>;

beforeEach(() => {
  authResult = { tenantId: "t1", isLoading: false };
  listResult = { data: policiesData, isLoading: false, error: null, refetch };
  iam.listPolicies.mockResolvedValue(policiesData);
  iam.deletePolicy.mockResolvedValue({});
  confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  confirmSpy.mockRestore();
});

describe("PoliciesPage", () => {
  it("shows the auth loading state", () => {
    authResult = { tenantId: "t1", isLoading: true };
    render(<PoliciesPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
  });

  it("asks to log in again without a tenant and does not list", async () => {
    authResult = { tenantId: undefined, isLoading: false };
    render(<PoliciesPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    await expect(apiCall.fn()).resolves.toEqual({ success: true, data: null });
    expect(iam.listPolicies).not.toHaveBeenCalled();
    // The delete mutation refuses to run without a tenant.
    await expect(mutationCall.fn("x")).rejects.toThrow("No tenant ID available");
  });

  it("lists the tenant's policies and toasts a load error", async () => {
    render(<PoliciesPage />);
    await expect(apiCall.fn()).resolves.toBe(policiesData);
    expect(iam.listPolicies).toHaveBeenCalledWith({ tenantId: "t1" });
    apiCall.opts.onError(new Error("down"));
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Error loading policies", description: "down", variant: "destructive" }),
    );
  });

  it("shows the load error with a retry", () => {
    listResult = { data: undefined, isLoading: false, error: new Error("list failed"), refetch };
    render(<PoliciesPage />);
    expect(screen.getByText("Error Loading Policies")).toBeTruthy();
    expect(screen.getByText("list failed")).toBeTruthy();
    fireEvent.click(screen.getByText("Retry"));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("renders the stats and rows with their fallbacks", () => {
    render(<PoliciesPage />);
    expect(statCard("Total Policies")).toBe("Total Policies3");
    // Priority 10 and below is high; a policy without labels counts none.
    expect(statCard("High Priority")).toBe("High Priority1");
    expect(statCard("With Labels")).toBe("With Labels1");
    const mid = within(screen.getByTestId("row-mid"));
    expect(mid.getByText("-")).toBeTruthy();
    expect(mid.getByText("50")).toBeTruthy();
    expect(mid.getByText("0")).toBeTruthy();
    expect(within(screen.getByTestId("row-p/high")).getByText("2")).toBeTruthy();
  });

  it("renders zero stats and no rows when the reply has no policies", () => {
    listResult = { data: {}, isLoading: true, error: null, refetch };
    render(<PoliciesPage />);
    expect(statCard("Total Policies")).toBe("Total Policies0");
    expect(statCard("High Priority")).toBe("High Priority0");
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
    expect(screen.queryByText(/^open /)).toBeNull();
  });

  it("routes to the new-policy form and to an encoded policy detail", () => {
    render(<PoliciesPage />);
    fireEvent.click(screen.getByText("Add Policy"));
    expect(router.push).toHaveBeenLastCalledWith("/iam/policies/new");
    fireEvent.click(screen.getByText("open p/high"));
    expect(router.push).toHaveBeenLastCalledWith("/iam/policies/p%2Fhigh");
    const row = within(screen.getByTestId("row-mid"));
    fireEvent.click(row.getByText("View"));
    expect(router.push).toHaveBeenLastCalledWith("/iam/policies/mid");
    router.push.mockClear();
    fireEvent.click(row.getByText("Edit"));
    expect(router.push).toHaveBeenCalledWith("/iam/policies/mid");
  });

  it("deletes a confirmed policy, toasts and refetches", async () => {
    render(<PoliciesPage />);
    fireEvent.click(within(screen.getByTestId("row-mid")).getByText("Delete"));
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(confirmSpy).toHaveBeenCalledWith('Are you sure you want to delete policy "mid"?');
    expect(iam.deletePolicy).toHaveBeenCalledWith("t1", "mid");
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Policy deleted", variant: "success" }));
  });

  it("does nothing when the delete is not confirmed", () => {
    confirmSpy.mockReturnValue(false);
    render(<PoliciesPage />);
    fireEvent.click(within(screen.getByTestId("row-mid")).getByText("Delete"));
    expect(mutation.mutate).not.toHaveBeenCalled();
    expect(iam.deletePolicy).not.toHaveBeenCalled();
  });

  it("toasts a failed delete and does not refetch", async () => {
    iam.deletePolicy.mockRejectedValue(new Error("forbidden"));
    render(<PoliciesPage />);
    fireEvent.click(within(screen.getByTestId("row-mid")).getByText("Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Error deleting policy", description: "forbidden" }),
      ),
    );
    expect(refetch).not.toHaveBeenCalled();
  });

  it("bulk-deletes every selected policy once confirmed", async () => {
    render(<PoliciesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(confirmSpy).toHaveBeenCalledWith("Are you sure you want to delete 3 policy(ies)?");
    expect(iam.deletePolicy.mock.calls).toEqual([
      ["t1", "p/high"],
      ["t1", "mid"],
      ["t1", "low"],
    ]);
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({
        title: "Policies deleted",
        description: "3 policy(ies) have been deleted successfully",
      }),
    );
  });

  it("skips the bulk delete when it is not confirmed", async () => {
    confirmSpy.mockReturnValue(false);
    render(<PoliciesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await Promise.resolve();
    expect(iam.deletePolicy).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });

  it("toasts when any bulk delete fails", async () => {
    iam.deletePolicy.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error("nope"));
    render(<PoliciesPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({
          title: "Error deleting policies",
          description: "Some policies could not be deleted",
        }),
      ),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});
