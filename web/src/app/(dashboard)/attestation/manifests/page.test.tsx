import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import ManifestsPage from "./page";

// useApi is driven by hand so each test sets the exact loading, error and
// data state the page renders; the fetcher and the onError option the page
// hands to useApi are captured and exercised on their own.
type ApiOptions = { onError?: (err: Error) => void };

const service = { listManifests: vi.fn() };
const toast = vi.fn();
const refetch = vi.fn();
const api: {
  state: { data: unknown; isLoading: boolean; error: Error | null };
  fetcher: (() => unknown) | null;
  options: ApiOptions | undefined;
} = {
  state: { data: null, isLoading: false, error: null },
  fetcher: null,
  options: undefined,
};

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => service,
  useToast: () => ({ toast }),
  useApi: (fetcher: () => unknown, _deps: unknown[], options?: ApiOptions) => {
    api.fetcher = fetcher;
    api.options = options;
    return { ...api.state, refetch };
  },
}));

const dayMs = 24 * 60 * 60 * 1000;

function daysAgo(days: number): string {
  return new Date(Date.now() - days * dayMs).toISOString();
}

const pcr = (index: number) => ({ index, value: "AAAA", algorithm: "SHA256" });

function manifestsFixture() {
  return {
    manifests: [
      // Recent and signed, with VMs: an active server manifest.
      {
        id: "m-active",
        hostId: "host-active",
        version: "2.1.0",
        timestamp: daysAgo(1),
        signature: "sig",
        host: { pcrs: [pcr(0), pcr(1)] },
        vms: [{ vmId: "vm-1", pcrs: [pcr(0)] }, { vmId: "vm-2" }],
      },
      // Recent but unsigned, no version, no VMs: a draft workstation.
      {
        id: "m-draft",
        hostId: "host-draft",
        timestamp: daysAgo(2),
        host: { pcrs: [pcr(7)] },
      },
      // Older than 30 days: archived even though it is signed.
      {
        id: "m-old",
        hostId: "host-old",
        version: "0.9.0",
        timestamp: daysAgo(31),
        signature: "sig",
        vms: [],
      },
    ],
  };
}

function statValue(title: string): string | null | undefined {
  // The status names also label table badges: take the card title outside the table.
  const titleEl = screen.getAllByText(title).find((el) => el.closest("table") === null);
  const card = titleEl?.parentElement?.parentElement;
  return card?.querySelector(".text-2xl")?.textContent;
}

function rowOf(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

describe("ManifestsPage", () => {
  beforeEach(() => {
    api.state = { data: null, isLoading: false, error: null };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("fetches the manifests from listManifests with no filter", () => {
    render(<ManifestsPage />);
    service.listManifests.mockReturnValue("pending");

    expect(api.fetcher?.()).toBe("pending");
    expect(service.listManifests).toHaveBeenCalledWith({});
  });

  it("toasts a destructive error when loading fails", () => {
    render(<ManifestsPage />);
    api.options?.onError?.(new Error("upstream down"));

    expect(toast).toHaveBeenCalledWith({
      title: "Error loading manifests",
      description: "upstream down",
      variant: "destructive",
    });
  });

  it("shows the loading state while the manifests load", () => {
    api.state = { data: null, isLoading: true, error: null };
    render(<ManifestsPage />);

    expect(screen.getByText("Loading manifests...")).toBeTruthy();
    expect(screen.queryByText("Attestation Manifests")).toBeNull();
  });

  it("shows the error with a retry that refetches, ahead of the loading state", () => {
    api.state = { data: null, isLoading: true, error: new Error("forbidden") };
    render(<ManifestsPage />);

    expect(screen.getByText("Error Loading Manifests")).toBeTruthy();
    expect(screen.getByText("forbidden")).toBeTruthy();
    expect(screen.queryByText("Loading manifests...")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("shows zero counts and the empty state with no data", () => {
    render(<ManifestsPage />);

    expect(statValue("Total Manifests")).toBe("0");
    expect(statValue("Active")).toBe("0");
    expect(statValue("Draft")).toBe("0");
    expect(statValue("Archived")).toBe("0");
    expect(screen.getByText("No manifests found")).toBeTruthy();
  });

  it("treats a response without a manifests list as empty", () => {
    api.state = { data: {}, isLoading: false, error: null };
    render(<ManifestsPage />);

    expect(statValue("Total Manifests")).toBe("0");
    expect(screen.getByText("No manifests found")).toBeTruthy();
  });

  it("classifies manifests as active, draft or archived and counts them", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<ManifestsPage />);

    expect(statValue("Total Manifests")).toBe("3");
    expect(statValue("Active")).toBe("1");
    expect(statValue("Draft")).toBe("1");
    expect(statValue("Archived")).toBe("1");

    expect(within(rowOf("Manifest host-active")).getByText("Active")).toBeTruthy();
    expect(within(rowOf("Manifest host-draft")).getByText("Draft")).toBeTruthy();
    expect(within(rowOf("Manifest host-old")).getByText("Archived")).toBeTruthy();
    expect(screen.queryByText("No manifests found")).toBeNull();
  });

  it("derives version, device type, PCR count and creator per manifest", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<ManifestsPage />);

    const active = within(rowOf("Manifest host-active"));
    expect(active.getByText("v2.1.0")).toBeTruthy();
    expect(active.getByText("server")).toBeTruthy();
    expect(active.getByText("3")).toBeTruthy();
    expect(active.getByText("host-active")).toBeTruthy();

    const draft = within(rowOf("Manifest host-draft"));
    expect(draft.getByText("v1.0.0")).toBeTruthy();
    expect(draft.getByText("workstation")).toBeTruthy();
    expect(draft.getByText("1")).toBeTruthy();

    // An empty VM list is a workstation, and no host section counts no PCR.
    const old = within(rowOf("Manifest host-old"));
    expect(old.getByText("workstation")).toBeTruthy();
    expect(old.getByText("0")).toBeTruthy();
  });

  it("refetches on Refresh", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<ManifestsPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: /Create Manifest/ })).toBeTruthy();
  });
});
