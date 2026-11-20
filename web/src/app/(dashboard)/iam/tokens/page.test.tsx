import * as React from "react";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import TokensPage from "./page";

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

const toast = vi.fn();
const refetch = vi.fn();
const iam = {
  listApps: vi.fn(),
  registerApp: vi.fn(),
  deleteApp: vi.fn(),
  rotateAppSecret: vi.fn(),
};
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
const mutationState = { isLoading: false };

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
    isLoading: mutationState.isLoading,
    mutate: (arg: unknown) => {
      void fn(arg).then(
        (result) => options.onSuccess?.(result),
        (err: Error) => options.onError?.(err),
      );
    },
  }),
}));

// The real table needs tanstack state; this one renders the page's own
// column cells and hands its bulk actions to buttons.
vi.mock("@/components/ui/data-table", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/ui/data-table")>()),
  DataTable: ({
    columns,
    data,
    loading,
    bulkActions,
  }: {
    columns: Col[];
    data: Row[];
    loading?: boolean;
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
              <div key={j} data-testid={`cell-${c.accessorKey ?? c.id}`}>
                {c.cell?.({ row: { original: r } })}
              </div>
            ))}
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

// Inline dialogs: open decides whether the content is in the tree, and a
// dismiss button stands in for Escape or an outside click.
vi.mock("@/components/ui/dialog", () => {
  const Pass = ({ children }: { children?: React.ReactNode }) => <>{children}</>;
  return {
    Dialog: ({
      open,
      onOpenChange,
      children,
    }: {
      open?: boolean;
      onOpenChange?: (open: boolean) => void;
      children?: React.ReactNode;
    }) =>
      open ? (
        <div role="dialog">
          {children}
          <button onClick={() => onOpenChange?.(false)}>dismiss</button>
        </div>
      ) : null,
    DialogContent: Pass,
    DialogDescription: ({ children }: { children?: React.ReactNode }) => <p>{children}</p>,
    DialogFooter: Pass,
    DialogHeader: Pass,
    DialogTitle: ({ children }: { children?: React.ReactNode }) => <h2>{children}</h2>,
  };
});

const apps = [
  {
    clientId: "client-ci",
    name: "ci-runner",
    grantTypes: ["client_credentials", "refresh_token", "authorization_code"],
    createdAt: "2020-01-01T00:00:00Z",
  },
  // No name, grant types or creation time: the client id stands in.
  { clientId: "client-bare" },
];

const confirm = vi.spyOn(window, "confirm");
const writeText = vi.fn();

beforeEach(() => {
  vi.clearAllMocks();
  authResult.tenantId = "tenant-1";
  authResult.isLoading = false;
  apiResult.data = { apps };
  apiResult.isLoading = false;
  apiResult.error = null;
  mutationState.isLoading = false;
  confirm.mockReturnValue(true);
  writeText.mockResolvedValue(undefined);
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
  });
});

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function rowFor(text: string): HTMLElement {
  const row = screen.getByText(text).closest("[data-testid='row']");
  if (!row) throw new Error(`no table row for ${text}`);
  return row as HTMLElement;
}

function stat(title: string): string | null | undefined {
  return screen.getByText(title, { selector: "h3" }).parentElement?.parentElement?.textContent;
}

function openRegister(name?: string) {
  fireEvent.click(screen.getByText("Register Application"));
  if (name !== undefined) {
    fireEvent.change(screen.getByPlaceholderText("My Application"), { target: { value: name } });
  }
  fireEvent.click(screen.getByText("Register"));
}

describe("TokensPage states", () => {
  it("shows the auth spinner while auth loads", () => {
    authResult.isLoading = true;
    render(<TokensPage />);
    expect(screen.getByText("Loading authentication...")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("asks for a login when there is no tenant", () => {
    authResult.tenantId = undefined;
    render(<TokensPage />);
    expect(screen.getByText("Authentication Required")).toBeTruthy();
    expect(screen.queryByTestId("table")).toBeNull();
  });

  it("shows the load error and retries on request", () => {
    apiResult.error = new Error("backend down");
    render(<TokensPage />);
    expect(screen.getByText("Error Loading Applications")).toBeTruthy();
    expect(screen.getByText("backend down")).toBeTruthy();
    fireEvent.click(screen.getByText("Retry"));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("passes the loading flag to the table", () => {
    apiResult.isLoading = true;
    render(<TokensPage />);
    expect(screen.getByTestId("table").getAttribute("data-loading")).toBe("true");
  });
});

describe("TokensPage fetching", () => {
  it("lists the tenant's applications", async () => {
    iam.listApps.mockResolvedValue({ success: true, data: { apps: [] } });
    render(<TokensPage />);
    await captured.fetcher?.();
    expect(iam.listApps).toHaveBeenCalledWith({ tenantId: "tenant-1" });
  });

  it("does not call the backend without a tenant", async () => {
    authResult.tenantId = undefined;
    render(<TokensPage />);
    await expect(captured.fetcher?.()).resolves.toEqual({ success: true, data: null });
    expect(iam.listApps).not.toHaveBeenCalled();
  });

  it("toasts a load error", () => {
    render(<TokensPage />);
    captured.options?.onError?.(new Error("timeout"));
    expect(toast).toHaveBeenCalledWith({
      title: "Error loading applications",
      description: "timeout",
      variant: "destructive",
    });
  });
});

describe("TokensPage rendering", () => {
  it("maps each application to a row with fallbacks", () => {
    render(<TokensPage />);
    expect(screen.getAllByTestId("row")).toHaveLength(2);

    const ci = rowFor("ci-runner");
    expect(within(ci).getByText("client-ci")).toBeTruthy();
    const grants = within(ci).getByTestId("cell-grantTypes").textContent;
    expect(grants).toBe("client_credentialsrefresh_token+1");
    expect(within(ci).getByTestId("cell-createdAt").textContent).toMatch(/ago$/);

    // The bare app shows its client id as both name and client id.
    const bare = screen.getAllByText("client-bare");
    expect(bare).toHaveLength(2);
    const bareRow = bare[0].closest("[data-testid='row']") as HTMLElement;
    expect(bare[1].closest("[data-testid='row']")).toBe(bareRow);
    expect(within(bareRow).getByTestId("cell-grantTypes").textContent).toBe("");
    expect(within(bareRow).getByTestId("cell-createdAt").textContent).toBe("-");
  });

  it("renders the column headers", () => {
    render(<TokensPage />);
    const headers = screen.getAllByTestId("header").map((h) => h.textContent);
    expect(headers).toEqual(["Application Name", "Client ID", "Grant Types", "Created", ""]);
  });

  it("totals the applications and distinct grant types", () => {
    render(<TokensPage />);
    expect(stat("Total Applications")).toBe("Total Applications2");
    expect(stat("Active")).toBe("Active2");
    expect(stat("Grant Types")).toBe("Grant Types3");
  });

  it.each([
    ["no data", null],
    ["no apps field", {}],
    ["an empty list", { apps: [] }],
  ])("shows an empty table for %s", (_name, data) => {
    apiResult.data = data;
    render(<TokensPage />);
    expect(screen.queryAllByTestId("row")).toHaveLength(0);
    expect(stat("Total Applications")).toBe("Total Applications0");
    expect(stat("Grant Types")).toBe("Grant Types0");
  });
});

describe("TokensPage register", () => {
  it("rejects an empty or blank name", () => {
    render(<TokensPage />);
    openRegister();
    openRegisterAgainWith("   ");
    expect(iam.registerApp).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledTimes(2);
    expect(toast).toHaveBeenCalledWith({
      title: "Validation error",
      description: "Application name is required",
      variant: "destructive",
    });
  });

  it("registers a trimmed name and shows the new secret", async () => {
    iam.registerApp.mockResolvedValue({
      app: { clientId: "client-new", clientSecret: "secret-new", name: "My App" },
    });
    render(<TokensPage />);
    openRegister("  My App  ");
    expect(iam.registerApp).toHaveBeenCalledWith({
      tenantId: "tenant-1",
      name: "My App",
      grantTypes: ["client_credentials"],
      redirectUris: [],
      responseTypes: [],
    });
    await screen.findByText("Application Credentials");
    expect(screen.getByText("secret-new")).toBeTruthy();
    expect(screen.getByText("client-new")).toBeTruthy();
    expect(screen.queryByPlaceholderText("My Application")).toBeNull();
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Application registered", variant: "success" }),
    );
  });

  it("clears the name after a registration", async () => {
    iam.registerApp.mockResolvedValue({ app: { clientId: "c", name: "n" } });
    render(<TokensPage />);
    openRegister("first");
    await waitFor(() => expect(refetch).toHaveBeenCalled());
    fireEvent.click(screen.getByText("Register Application"));
    expect((screen.getByPlaceholderText("My Application") as HTMLInputElement).value).toBe("");
  });

  it.each([
    ["no secret", { app: { clientId: "c", name: "n" } }],
    ["no app", {}],
    ["no result", undefined],
  ])("shows no secret dialog for %s", async (_name, result) => {
    iam.registerApp.mockResolvedValue(result);
    render(<TokensPage />);
    openRegister("x");
    await waitFor(() => expect(refetch).toHaveBeenCalled());
    expect(screen.queryByText("Application Credentials")).toBeNull();
  });

  it("toasts a failed registration and keeps the form open", async () => {
    iam.registerApp.mockRejectedValue(new Error("duplicate"));
    render(<TokensPage />);
    openRegister("dup");
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error registering application",
        description: "duplicate",
        variant: "destructive",
      }),
    );
    expect(screen.getByPlaceholderText("My Application")).toBeTruthy();
    expect(refetch).not.toHaveBeenCalled();
  });

  it("closes the form on Cancel", () => {
    render(<TokensPage />);
    fireEvent.click(screen.getByText("Register Application"));
    fireEvent.click(screen.getByText("Cancel"));
    expect(screen.queryByPlaceholderText("My Application")).toBeNull();
  });

  it("disables Register while a registration runs", () => {
    mutationState.isLoading = true;
    render(<TokensPage />);
    fireEvent.click(screen.getByText("Register Application"));
    expect((screen.getByText("Register").closest("button") as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});

function openRegisterAgainWith(name: string) {
  fireEvent.change(screen.getByPlaceholderText("My Application"), { target: { value: name } });
  fireEvent.click(screen.getByText("Register"));
}

describe("TokensPage rotate secret", () => {
  it("rotates a confirmed secret and shows the new one", async () => {
    iam.rotateAppSecret.mockResolvedValue({
      clientId: "client-ci",
      clientSecret: "rotated",
      name: "ci-runner",
    });
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Rotate Secret"));
    expect(confirm).toHaveBeenCalledWith(
      'Are you sure you want to rotate the secret for "ci-runner"? The old secret will stop working immediately.',
    );
    expect(iam.rotateAppSecret).toHaveBeenCalledWith("tenant-1", "client-ci");
    await screen.findByText("rotated");
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Secret rotated", variant: "success" }),
    );
  });

  it("shows no dialog when the rotation returns nothing", async () => {
    iam.rotateAppSecret.mockResolvedValue(null);
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Rotate Secret"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Secret rotated" })),
    );
    expect(screen.queryByText("Application Credentials")).toBeNull();
  });

  it("keeps the secret when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Rotate Secret"));
    expect(iam.rotateAppSecret).not.toHaveBeenCalled();
  });

  it("toasts a failed rotation", async () => {
    iam.rotateAppSecret.mockRejectedValue(new Error("locked"));
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Rotate Secret"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error rotating secret",
        description: "locked",
        variant: "destructive",
      }),
    );
  });
});

describe("TokensPage secret dialog", () => {
  async function showSecret() {
    iam.rotateAppSecret.mockResolvedValue({
      clientId: "client-ci",
      clientSecret: "shown-once",
      name: "ci-runner",
    });
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Rotate Secret"));
    return screen.findByText("shown-once");
  }

  it("copies the secret and resets the copied mark", async () => {
    const secret = await showSecret();
    const copy = secret.parentElement?.querySelector("button") as HTMLButtonElement;
    const before = copy.innerHTML;
    vi.useFakeTimers({ toFake: ["setTimeout"] });
    await act(async () => {
      fireEvent.click(copy);
    });
    expect(writeText).toHaveBeenCalledWith("shown-once");
    expect(copy.innerHTML).not.toBe(before);
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(copy.innerHTML).toBe(before);
  });

  it("closes on Close", async () => {
    await showSecret();
    fireEvent.click(screen.getByText("Close"));
    expect(screen.queryByText("shown-once")).toBeNull();
  });

  it("closes when dismissed", async () => {
    await showSecret();
    fireEvent.click(screen.getByText("dismiss"));
    expect(screen.queryByText("shown-once")).toBeNull();
  });
});

describe("TokensPage delete", () => {
  it("deletes a confirmed application and refetches", async () => {
    iam.deleteApp.mockResolvedValue({ success: true });
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Delete"));
    expect(confirm).toHaveBeenCalledWith('Are you sure you want to delete "ci-runner"?');
    expect(iam.deleteApp).toHaveBeenCalledWith("tenant-1", "client-ci");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Application deleted", variant: "success" }),
    );
  });

  it("keeps the application when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Delete"));
    expect(iam.deleteApp).not.toHaveBeenCalled();
  });

  it("toasts a failed delete without refetching", async () => {
    iam.deleteApp.mockRejectedValue(new Error("forbidden"));
    render(<TokensPage />);
    fireEvent.click(within(rowFor("ci-runner")).getByText("Delete"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting application",
        description: "forbidden",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});

describe("TokensPage bulk delete", () => {
  it("deletes every selected application", async () => {
    iam.deleteApp.mockResolvedValue({ success: true });
    render(<TokensPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(confirm).toHaveBeenCalledWith("Are you sure you want to delete 2 application(s)?");
    await waitFor(() => expect(refetch).toHaveBeenCalledTimes(1));
    expect(iam.deleteApp.mock.calls).toEqual([
      ["tenant-1", "client-ci"],
      ["tenant-1", "client-bare"],
    ]);
    expect(toast).toHaveBeenCalledWith({
      title: "Applications deleted",
      description: "2 application(s) have been deleted successfully",
      variant: "success",
    });
  });

  it("does nothing when the prompt is cancelled", () => {
    confirm.mockReturnValue(false);
    render(<TokensPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    expect(iam.deleteApp).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();
  });

  it("reports a partial failure", async () => {
    iam.deleteApp.mockResolvedValueOnce({ success: true }).mockRejectedValueOnce(new Error("no"));
    render(<TokensPage />);
    fireEvent.click(screen.getByText("Delete selected"));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error deleting applications",
        description: "Some applications could not be deleted",
        variant: "destructive",
      }),
    );
    expect(refetch).not.toHaveBeenCalled();
  });
});
