import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ReactNode } from "react";

// #2054: the applications list's Rotate Secret action calls the SDK's
// iam.rotateAppSecret and shows the new client secret once.

type MutationOpts = {
  onSuccess?: (data: unknown, vars: unknown) => void;
  onError?: (err: Error, vars: unknown) => void;
};

const { toast, iam } = vi.hoisted(() => ({
  toast: vi.fn(),
  iam: { listApps: vi.fn(), deleteApp: vi.fn(), rotateAppSecret: vi.fn() },
}));

vi.mock("@/hooks", () => ({
  useIAM: () => iam,
  useToast: () => ({ toast }),
  useApi: () => ({
    data: { apps: [{ clientId: "app-1", name: "billing", redirectUris: [], grantTypes: [] }] },
    isLoading: false,
    error: undefined,
    refetch: vi.fn(),
  }),
  useMutation: (fn: (v: unknown) => Promise<{ data: unknown }>, opts?: MutationOpts) => ({
    mutate: async (v: unknown) => {
      try {
        const r = await fn(v);
        opts?.onSuccess?.(r.data, v);
      } catch (e) {
        opts?.onError?.(e as Error, v);
      }
    },
    isLoading: false,
  }),
}));

vi.mock("@/contexts/AuthContext", () => ({
  useAuth: () => ({ tenantId: "tenant-1", isLoading: false }),
}));

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }));

type Row = Record<string, unknown> & { clientId: string };
type Column = { id?: string; accessorKey?: string; cell?: (ctx: { row: { getValue: (k: string) => unknown; original: Row } }) => ReactNode };

vi.mock("@/components/ui/data-table", () => ({
  createSelectColumn: () => ({ id: "select" }),
  DataTable: ({ columns, data }: { columns: Column[]; data: Row[] }) => (
    <div>
      {data.map((r) => (
        <div key={r.clientId} data-testid={`row-${r.clientId}`}>
          {columns
            .filter((c) => c.cell)
            .map((c, i) => (
              <div key={i} data-col={c.accessorKey ?? c.id}>
                {c.cell!({ row: { getValue: (k) => r[k], original: r } })}
              </div>
            ))}
        </div>
      ))}
    </div>
  ),
}));

vi.mock("@/components/ui/data-table-row-actions", () => ({
  DataTableRowActions: ({
    row,
    actions,
  }: {
    row: Row;
    actions: { label: string; onClick: (r: Row) => void; disabled?: boolean; title?: string }[];
  }) => (
    <div>
      {actions.map((a) => (
        <button key={a.label} onClick={() => a.onClick(row)} disabled={a.disabled} title={a.title}>
          {a.label}
        </button>
      ))}
    </div>
  ),
}));

const { off } = vi.hoisted(() => ({ off: new Set<string>() }));

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: iam" } : { enabled: true },
  }),
}));

const ROTATE_OP = "POST /api/v1/iam/tenants/{tenant}/apps/{id}/rotate";

import AppsPage from "./page";

function clickRotate() {
  fireEvent.click(within(screen.getByTestId("row-app-1")).getByRole("button", { name: "Rotate Secret" }));
}

beforeEach(() => {
  toast.mockReset();
  iam.rotateAppSecret.mockReset();
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  off.clear();
});

describe("AppsPage Rotate Secret capability gate (#2054)", () => {
  it("disables Rotate Secret with the reason when the rotate op is off", async () => {
    off.add(ROTATE_OP);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<AppsPage />);
    const button = within(screen.getByTestId("row-app-1")).getByRole("button", {
      name: "Rotate Secret",
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: iam");
    fireEvent.click(button);
    await Promise.resolve();
    expect(confirm).not.toHaveBeenCalled();
    expect(iam.rotateAppSecret).not.toHaveBeenCalled();
  });

  it("leaves Rotate Secret enabled when the rotate op is offered", () => {
    render(<AppsPage />);
    const button = within(screen.getByTestId("row-app-1")).getByRole("button", {
      name: "Rotate Secret",
    }) as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });
});

describe("AppsPage Rotate Secret", () => {
  it("rotates the app's secret through the SDK and shows the new secret", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    iam.rotateAppSecret.mockResolvedValue({
      success: true,
      data: { clientId: "app-1", name: "billing", clientSecret: "rotated-secret-1", timestamp: "t" },
    });
    render(<AppsPage />);
    clickRotate();
    await waitFor(() => expect(screen.getByText("rotated-secret-1")).toBeTruthy());
    expect(iam.rotateAppSecret).toHaveBeenCalledTimes(1);
    expect(iam.rotateAppSecret).toHaveBeenCalledWith("tenant-1", "app-1");
  });

  it("does not rotate when the confirm is declined", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    render(<AppsPage />);
    clickRotate();
    await Promise.resolve();
    expect(iam.rotateAppSecret).not.toHaveBeenCalled();
  });

  it("shows a secret the server writes as snake_case client_secret", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    iam.rotateAppSecret.mockResolvedValue({
      success: true,
      data: { client_id: "app-1", name: "billing", client_secret: "rotated-secret-2" },
    });
    render(<AppsPage />);
    clickRotate();
    await waitFor(() => expect(screen.getByText("rotated-secret-2")).toBeTruthy());
  });

  it("toasts a destructive error and shows no secret when the rotate fails", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    iam.rotateAppSecret.mockRejectedValue(new Error("boom"));
    render(<AppsPage />);
    clickRotate();
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ variant: "destructive" })),
    );
    expect(iam.rotateAppSecret).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/rotated-secret/)).toBeNull();
  });
});
