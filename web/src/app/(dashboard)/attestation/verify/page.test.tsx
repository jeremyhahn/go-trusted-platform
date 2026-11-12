import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import VerifyPage from "./page";

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

const manifestsFixture = {
  manifests: [
    { id: "m-1", hostId: "host-merkle", timestamp: "2026-08-31T10:00:00Z", signature: "sig", merkleRoot: "root" },
    { id: "m-2", hostId: "host-signed", timestamp: "2026-08-31T10:00:00Z", signature: "sig" },
    { id: "m-3", hostId: "host-unsigned", timestamp: "2026-08-31T10:00:00Z" },
    { id: "m-4", hostId: "host-empty-sig", timestamp: "2026-08-31T10:00:00Z", signature: "" },
  ],
};

function card(title: string): HTMLElement | null | undefined {
  // The result names also label table badges: take the card title outside the table.
  const titleEl = screen.getAllByText(title).find((el) => el.closest("table") === null);
  return titleEl?.parentElement?.parentElement;
}

function statValue(title: string): string | null | undefined {
  return card(title)?.querySelector(".text-2xl")?.textContent;
}

function rowOf(name: string): HTMLElement {
  const row = screen.getByText(name).closest("tr");
  if (!row) throw new Error(`no row for ${name}`);
  return row;
}

describe("VerifyPage", () => {
  beforeEach(() => {
    api.state = { data: null, isLoading: false, error: null };
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("fetches the verification history from listManifests with no filter", () => {
    render(<VerifyPage />);
    service.listManifests.mockReturnValue("pending");

    expect(api.fetcher?.()).toBe("pending");
    expect(service.listManifests).toHaveBeenCalledWith({});
  });

  it("toasts a destructive error when loading fails", () => {
    render(<VerifyPage />);
    api.options?.onError?.(new Error("upstream down"));

    expect(toast).toHaveBeenCalledWith({
      title: "Error loading verifications",
      description: "upstream down",
      variant: "destructive",
    });
  });

  it("shows the loading state while the history loads", () => {
    api.state = { data: null, isLoading: true, error: null };
    render(<VerifyPage />);

    expect(screen.getByText("Loading verifications...")).toBeTruthy();
    expect(screen.queryByText("Attestation Verification")).toBeNull();
  });

  it("shows the error with a retry that refetches, ahead of the loading state", () => {
    api.state = { data: null, isLoading: true, error: new Error("forbidden") };
    render(<VerifyPage />);

    expect(screen.getByText("Error Loading Verifications")).toBeTruthy();
    expect(screen.getByText("forbidden")).toBeTruthy();
    expect(screen.queryByText("Loading verifications...")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("shows zero counts, a 0% success rate and the empty state with no data", () => {
    render(<VerifyPage />);

    expect(statValue("Total Verifications")).toBe("0");
    expect(statValue("Passed")).toBe("0");
    expect(statValue("Failed")).toBe("0");
    expect(statValue("Warning")).toBe("0");
    expect(statValue("In Progress")).toBe("0");
    expect(card("Passed")?.textContent).toContain("0% success rate");
    expect(screen.getByText("No verifications found")).toBeTruthy();
  });

  it("treats a response without a manifests list as empty", () => {
    api.state = { data: {}, isLoading: false, error: null };
    render(<VerifyPage />);

    expect(statValue("Total Verifications")).toBe("0");
    expect(screen.getByText("No verifications found")).toBeTruthy();
  });

  it("marks signed manifests passed and unsigned ones in progress", () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    expect(statValue("Total Verifications")).toBe("4");
    expect(statValue("Passed")).toBe("2");
    expect(statValue("Failed")).toBe("0");
    expect(statValue("Warning")).toBe("0");
    expect(statValue("In Progress")).toBe("2");
    expect(card("Passed")?.textContent).toContain("50.0% success rate");

    expect(within(rowOf("Manifest host-merkle")).getByText("Passed")).toBeTruthy();
    expect(within(rowOf("Manifest host-signed")).getByText("Passed")).toBeTruthy();
    expect(within(rowOf("Manifest host-unsigned")).getByText("In Progress")).toBeTruthy();
    // An empty signature is no signature.
    expect(within(rowOf("Manifest host-empty-sig")).getByText("In Progress")).toBeTruthy();
    expect(screen.queryByText("No verifications found")).toBeNull();
  });

  it("names the manifest and reports no PCR mismatch per row", () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    const row = within(rowOf("Manifest host-merkle"));
    expect(row.getByText("Manifest host-merkle")).toBeTruthy();
    const mismatches = row.getByText("0");
    expect(mismatches.className).toContain("text-green-600");
  });

  it("rounds the success rate to one decimal", () => {
    api.state = {
      data: { manifests: manifestsFixture.manifests.slice(0, 3) },
      isLoading: false,
      error: null,
    };
    render(<VerifyPage />);

    expect(card("Passed")?.textContent).toContain("66.7% success rate");
  });

  it("refetches on Refresh and offers Run Verification", () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: /Run Verification/ })).toBeTruthy();
  });
});
