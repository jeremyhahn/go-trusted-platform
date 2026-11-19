import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import QuotesPage from "./page";

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
      {
        id: "m-1",
        hostId: "host-signed",
        timestamp: daysAgo(1),
        signature: "sig",
        nonce: "0123456789abcdef",
        host: { hashAlgorithm: "SHA256", timestamp: daysAgo(1), pcrs: [pcr(0), pcr(4), pcr(7)] },
        vms: [
          { vmId: "vm-signed", hashAlgorithm: "SHA384", timestamp: daysAgo(1), signature: "s", pcrs: [pcr(1)] },
          { vmId: "vm-unsigned", hashAlgorithm: "SHA256", timestamp: daysAgo(2), pcrs: [pcr(2), pcr(3)] },
          { vmId: "vm-expired", hashAlgorithm: "SHA1", timestamp: daysAgo(8), signature: "s", pcrs: [pcr(5)] },
        ],
      },
      // Unsigned host quote.
      {
        id: "m-2",
        hostId: "host-unsigned",
        timestamp: daysAgo(3),
        host: { hashAlgorithm: "SHA512", timestamp: daysAgo(3), pcrs: [pcr(10)] },
      },
      // Older than seven days: expired even though it is signed.
      {
        id: "m-3",
        hostId: "host-expired",
        timestamp: daysAgo(9),
        signature: "sig",
        host: { hashAlgorithm: "SHA256", timestamp: daysAgo(9), pcrs: [pcr(0)] },
      },
      // No host section and no VMs: no quote at all.
      { id: "m-4", hostId: "host-none", timestamp: daysAgo(1) },
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

describe("QuotesPage", () => {
  beforeEach(() => {
    api.state = { data: null, isLoading: false, error: null };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("fetches the quotes from listManifests with no filter", () => {
    render(<QuotesPage />);
    service.listManifests.mockReturnValue("pending");

    expect(api.fetcher?.()).toBe("pending");
    expect(service.listManifests).toHaveBeenCalledWith({});
  });

  it("toasts a destructive error when loading fails", () => {
    render(<QuotesPage />);
    api.options?.onError?.(new Error("upstream down"));

    expect(toast).toHaveBeenCalledWith({
      title: "Error loading quotes",
      description: "upstream down",
      variant: "destructive",
    });
  });

  it("shows the loading state while the quotes load", () => {
    api.state = { data: null, isLoading: true, error: null };
    render(<QuotesPage />);

    expect(screen.getByText("Loading quotes...")).toBeTruthy();
    expect(screen.queryByText("TPM Quotes")).toBeNull();
  });

  it("shows the error with a retry that refetches, ahead of the loading state", () => {
    api.state = { data: null, isLoading: true, error: new Error("forbidden") };
    render(<QuotesPage />);

    expect(screen.getByText("Error Loading Quotes")).toBeTruthy();
    expect(screen.getByText("forbidden")).toBeTruthy();
    expect(screen.queryByText("Loading quotes...")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("shows zero counts and the empty state with no data", () => {
    render(<QuotesPage />);

    expect(statValue("Total Quotes")).toBe("0");
    expect(statValue("Signed")).toBe("0");
    expect(statValue("Unsigned")).toBe("0");
    expect(statValue("Expired")).toBe("0");
    expect(screen.getByText("No quotes found")).toBeTruthy();
  });

  it("treats a response without a manifests list as empty", () => {
    api.state = { data: {}, isLoading: false, error: null };
    render(<QuotesPage />);

    expect(statValue("Total Quotes")).toBe("0");
    expect(screen.getByText("No quotes found")).toBeTruthy();
  });

  it("extracts host and VM quotes and counts signed, unsigned and expired", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<QuotesPage />);

    expect(statValue("Total Quotes")).toBe("6");
    expect(statValue("Signed")).toBe("2");
    expect(statValue("Unsigned")).toBe("2");
    expect(statValue("Expired")).toBe("2");
    expect(screen.queryByText("host-none")).toBeNull();
    expect(screen.queryByText("No quotes found")).toBeNull();

    expect(within(rowOf("host-signed")).getByText("Signed")).toBeTruthy();
    expect(within(rowOf("host-unsigned")).getByText("Unsigned")).toBeTruthy();
    expect(within(rowOf("host-expired")).getByText("Expired")).toBeTruthy();
    expect(within(rowOf("VM: vm-signed")).getByText("Signed")).toBeTruthy();
    expect(within(rowOf("VM: vm-unsigned")).getByText("Unsigned")).toBeTruthy();
    expect(within(rowOf("VM: vm-expired")).getByText("Expired")).toBeTruthy();
  });

  it("shows the TPM kind, algorithm and PCR range of each quote", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<QuotesPage />);

    const host = within(rowOf("host-signed"));
    expect(host.getByText("TPM 2.0 TPM")).toBeTruthy();
    expect(host.getByText("SHA256")).toBeTruthy();
    expect(host.getByText("3 PCRs (0-7)")).toBeTruthy();

    const vm = within(rowOf("VM: vm-unsigned"));
    expect(vm.getByText("vTPM 2.0 TPM")).toBeTruthy();
    expect(vm.getByText("2 PCRs (2-3)")).toBeTruthy();

    expect(within(rowOf("host-unsigned")).getByText("1 PCRs (10-10)")).toBeTruthy();
  });

  it("lists a host quote without PCRs as zero PCRs", () => {
    api.state = {
      data: {
        manifests: [
          { id: "m-5", hostId: "host-bare", timestamp: daysAgo(1), signature: "s", host: { hashAlgorithm: "SHA256", timestamp: daysAgo(1) } },
        ],
      },
      isLoading: false,
      error: null,
    };
    render(<QuotesPage />);

    expect(statValue("Total Quotes")).toBe("1");
    expect(within(rowOf("host-bare")).getByText(/^0 PCRs/)).toBeTruthy();
  });

  it("refetches on Refresh", () => {
    api.state = { data: manifestsFixture(), isLoading: false, error: null };
    render(<QuotesPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});
