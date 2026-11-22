import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { ColumnDef } from "@tanstack/react-table";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CertificateRequest } from "@/types/security";
import CertificateRequestsPage from "./page";

// The page holds its requests in local state, which no SDK call fills yet
// (the CSR endpoints do not exist). DataTable is stubbed: it records the data
// and filters it is given and renders every column cell for the fixture rows
// below, so the cell renderers and row actions are reachable.

type MutationOptions = {
  onSuccess?: (r: unknown) => void;
  onError?: (e: Error) => void;
};

const toast = vi.fn();
let fixtureRows: CertificateRequest[] = [];
let tableProps: { data: CertificateRequest[]; filterableColumns: unknown; searchKey: string; loading: boolean } | null;
let mutationImpl: ((fn: (v: string) => Promise<unknown>, v: string) => Promise<unknown>) | null = null;

vi.mock("@/hooks", () => ({
  useCA: () => ({}),
  useToast: () => ({ toast }),
  useMutation: (fn: (v: string) => Promise<unknown>, opts: MutationOptions) => ({
    isLoading: false,
    mutate: async (v: string) => {
      try {
        const r = mutationImpl ? await mutationImpl(fn, v) : await fn(v);
        opts.onSuccess?.(r);
      } catch (e) {
        opts.onError?.(e as Error);
      }
    },
  }),
}));

vi.mock("@/components/ui/data-table", () => ({
  createSelectColumn: () => ({ id: "select" }),
  DataTable: (props: {
    columns: ColumnDef<CertificateRequest>[];
    data: CertificateRequest[];
    filterableColumns: unknown;
    searchKey: string;
    loading: boolean;
  }) => {
    tableProps = props;
    return (
      <div>
        {fixtureRows.map((r) => (
          <div key={r.id} data-testid={`row-${r.id}`}>
            {props.columns.map((c, i) => {
              const cell = (c as { cell?: unknown }).cell;
              if (typeof cell !== "function") return null;
              const row = { original: r, getValue: (k: keyof CertificateRequest) => r[k] };
              return <div key={i}>{cell({ row })}</div>;
            })}
          </div>
        ))}
      </div>
    );
  },
}));

vi.mock("@/components/ui/data-table-column-header", () => ({
  DataTableColumnHeader: ({ title }: { title: string }) => <span>{title}</span>,
}));

vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({
    row,
    actions,
  }: {
    row: CertificateRequest;
    actions: { label: string; onClick: (r: CertificateRequest) => void }[];
  }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(row)}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

vi.mock("@/components/features/ca/csr-viewer", () => ({
  CSRViewer: ({ csr, subject }: { csr: string; subject: string }) => (
    <div data-testid="csr-viewer">
      {subject}|{csr}
    </div>
  ),
}));

function req(over: Partial<CertificateRequest>): CertificateRequest {
  return {
    id: "r1",
    requester: "alice",
    subject: "CN=device-1",
    type: "leaf",
    requestedAt: "2026-11-01T10:00:00Z",
    status: "pending",
    csr: "CSR-PEM",
    ...over,
  } as CertificateRequest;
}

const pending = req({});
const approved = req({ id: "r2", requester: "bob", status: "approved", type: "intermediate" });
const denied = req({ id: "r3", requester: "carol", status: "denied" });

describe("CertificateRequestsPage", () => {
  beforeEach(() => {
    toast.mockReset();
    fixtureRows = [];
    tableProps = null;
    mutationImpl = null;
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("renders an empty, non-loading table searched by subject with no error", () => {
    render(<CertificateRequestsPage />);
    expect(screen.getByText("Certificate Requests")).toBeTruthy();
    expect(tableProps?.data).toEqual([]);
    expect(tableProps?.searchKey).toBe("subject");
    expect(tableProps?.loading).toBe(false);
    expect(screen.queryByText("Error")).toBeNull();
  });

  it("offers the type and status filters", () => {
    render(<CertificateRequestsPage />);
    expect(tableProps?.filterableColumns).toEqual([
      {
        id: "type",
        title: "Type",
        options: [
          { label: "Root", value: "root" },
          { label: "Intermediate", value: "intermediate" },
          { label: "Leaf", value: "leaf" },
        ],
      },
      {
        id: "status",
        title: "Status",
        options: [
          { label: "Pending", value: "pending" },
          { label: "Approved", value: "approved" },
          { label: "Denied", value: "denied" },
        ],
      },
    ]);
  });

  it("logs on Refresh, since CSR listing is not implemented", () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    render(<CertificateRequestsPage />);
    const refresh = screen.getByRole("button", { name: /Refresh/ }) as HTMLButtonElement;
    expect(refresh.disabled).toBe(false);
    fireEvent.click(refresh);
    expect(log).toHaveBeenCalledWith("Refetch CSRs - not yet implemented");
  });

  it("renders each cell and offers Approve and Deny only for pending rows", () => {
    fixtureRows = [pending, approved, denied];
    render(<CertificateRequestsPage />);
    const p = within(screen.getByTestId("row-r1"));
    expect(p.getByText("alice")).toBeTruthy();
    expect(p.getByText("CN=device-1")).toBeTruthy();
    expect(p.getByText("leaf")).toBeTruthy();
    expect(p.getByText("pending")).toBeTruthy();
    const at = new Date("2026-11-01T10:00:00Z");
    expect(p.getByText(at.toLocaleDateString())).toBeTruthy();
    expect(p.getByText(at.toLocaleTimeString())).toBeTruthy();
    expect(p.getByRole("button", { name: "Approve" })).toBeTruthy();
    expect(p.getByRole("button", { name: "Deny" })).toBeTruthy();

    for (const id of ["row-r2", "row-r3"]) {
      const r = within(screen.getByTestId(id));
      expect(r.getByRole("button", { name: "View CSR" })).toBeTruthy();
      expect(r.queryByRole("button", { name: "Approve" })).toBeNull();
      expect(r.queryByRole("button", { name: "Deny" })).toBeNull();
    }
    expect(within(screen.getByTestId("row-r2")).getByText("approved")).toBeTruthy();
    expect(within(screen.getByTestId("row-r3")).getByText("denied")).toBeTruthy();
  });

  it("renders Invalid Date for a malformed requestedAt", () => {
    fixtureRows = [req({ requestedAt: "not-a-date" })];
    render(<CertificateRequestsPage />);
    expect(within(screen.getByTestId("row-r1")).getAllByText("Invalid Date").length).toBeGreaterThan(0);
  });

  it("approves after confirmation and toasts success", async () => {
    const confirmSpy = vi.fn(() => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.spyOn(console, "log").mockImplementation(() => {});
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Success",
        description: "Certificate request approved and certificate issued",
      })
    );
    expect(confirmSpy).toHaveBeenCalledWith("Approve certificate request from alice?");
  });

  it("does not approve when the confirmation is declined", () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(toast).not.toHaveBeenCalled();
  });

  it("denies with a reason and toasts success", async () => {
    vi.stubGlobal("prompt", vi.fn(() => "bad key"));
    vi.spyOn(console, "log").mockImplementation(() => {});
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Success", description: "Certificate request denied" })
    );
  });

  it("does not deny when the reason is empty or cancelled", () => {
    const promptSpy = vi.fn<() => string | null>().mockReturnValueOnce("").mockReturnValueOnce(null);
    vi.stubGlobal("prompt", promptSpy);
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(promptSpy).toHaveBeenCalledTimes(2);
    expect(toast).not.toHaveBeenCalled();
  });

  it("toasts a destructive error when a mutation fails", async () => {
    vi.stubGlobal("confirm", vi.fn(() => true));
    vi.stubGlobal("prompt", vi.fn(() => "r"));
    mutationImpl = () => Promise.reject(new Error("ca refused"));
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    fireEvent.click(screen.getByRole("button", { name: "Deny" }));
    await waitFor(() => expect(toast).toHaveBeenCalledTimes(2));
    expect(toast).toHaveBeenCalledWith({ title: "Error", description: "ca refused", variant: "destructive" });
  });

  it("opens the CSR dialog with the request details and acts from it", async () => {
    const confirmSpy = vi.fn(() => true);
    vi.stubGlobal("confirm", confirmSpy);
    vi.stubGlobal("prompt", vi.fn(() => "no"));
    vi.spyOn(console, "log").mockImplementation(() => {});
    fixtureRows = [pending];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "View CSR" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Certificate Signing Request")).toBeTruthy();
    expect(within(dialog).getByText("alice")).toBeTruthy();
    expect(within(dialog).getByTestId("csr-viewer").textContent).toBe("CN=device-1|CSR-PEM");

    fireEvent.click(within(dialog).getByRole("button", { name: /Approve/ }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await waitFor(() => expect(toast).toHaveBeenCalledTimes(1));
    expect(confirmSpy).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "View CSR" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: /Deny/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "Success", description: "Certificate request denied" })
    );
  });

  it("shows no Approve or Deny in the dialog for a decided request", async () => {
    fixtureRows = [approved];
    render(<CertificateRequestsPage />);
    fireEvent.click(screen.getByRole("button", { name: "View CSR" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("bob")).toBeTruthy();
    expect(within(dialog).queryByRole("button", { name: /Approve/ })).toBeNull();
    expect(within(dialog).queryByRole("button", { name: /Deny/ })).toBeNull();
  });
});
