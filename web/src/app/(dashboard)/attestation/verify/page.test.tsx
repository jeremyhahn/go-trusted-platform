import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import VerifyPage from "./page";

// useApi is driven by hand so each test sets the exact loading, error and
// data state the page renders; the fetcher and the onError option the page
// hands to useApi are captured and exercised on their own.
type ApiOptions = { onError?: (err: Error) => void };

const service = { listManifests: vi.fn(), verifyManifest: vi.fn() };
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

// Every manifest carries a signature and a Merkle root: only the verifier's
// verdict decides the result, never the presence of a signature.
function manifest(id: string, hostId: string) {
  return { id, hostId, timestamp: "2026-08-31T10:00:00Z", signature: "sig", merkleRoot: "root" };
}

const manifestsFixture = {
  manifests: [
    manifest("m-1", "host-verified"),
    manifest("m-2", "host-failed"),
    manifest("m-3", "host-invalid"),
    manifest("m-4", "host-rejected"),
    manifest("m-5", "host-pending"),
  ],
};

function result(status: string, errors: string[] = []) {
  return { success: true, data: { status: { success: true, message: "" }, result: { status, errors } } };
}

// The verifier's answer per manifest id. A missing entry rejects the call.
const verdicts: Record<string, unknown> = {
  "m-1": result("VERIFIED"),
  "m-2": result("FAILED", ["signature does not verify"]),
  // Invalid evidence: the verifier answers but gives no result.
  "m-3": { success: false, error: { code: "INVALID_ARGUMENT", message: "bad manifest" } },
  "m-5": result("PENDING"),
};

function answerFromVerdicts() {
  service.verifyManifest.mockImplementation(({ manifest: m }: { manifest: { id: string } }) =>
    m.id in verdicts ? Promise.resolve(verdicts[m.id]) : Promise.reject(new Error("verifier unreachable")),
  );
}

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
    answerFromVerdicts();
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
    expect(statValue("Unverified")).toBe("0");
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

  it("asks the verifier about every listed manifest", async () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    await waitFor(() => expect(service.verifyManifest).toHaveBeenCalledTimes(5));
    expect(service.verifyManifest).toHaveBeenCalledWith({ manifest: manifestsFixture.manifests[0] });
  });

  it("shows a signed manifest in progress, never passed, until the verifier answers", () => {
    service.verifyManifest.mockReturnValue(new Promise(() => {}));
    api.state = { data: { manifests: [manifest("m-1", "host-verified")] }, isLoading: false, error: null };
    render(<VerifyPage />);

    expect(within(rowOf("Manifest host-verified")).getByText("In Progress")).toBeTruthy();
    expect(statValue("Passed")).toBe("0");
    expect(card("Passed")?.textContent).toContain("0.0% success rate");
  });

  it("takes each result from the verifier's verdict", async () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    await waitFor(() => expect(within(rowOf("Manifest host-verified")).getByText("Passed")).toBeTruthy());
    await waitFor(() => expect(within(rowOf("Manifest host-rejected")).getByText("Unverified")).toBeTruthy());
    expect(within(rowOf("Manifest host-failed")).getByText("Failed")).toBeTruthy();
    expect(within(rowOf("Manifest host-invalid")).getByText("Unverified")).toBeTruthy();
    expect(within(rowOf("Manifest host-pending")).getByText("In Progress")).toBeTruthy();

    expect(statValue("Total Verifications")).toBe("5");
    expect(statValue("Passed")).toBe("1");
    expect(statValue("Failed")).toBe("1");
    expect(statValue("Unverified")).toBe("2");
    expect(statValue("In Progress")).toBe("1");
    expect(card("Passed")?.textContent).toContain("20.0% success rate");
    expect(screen.queryByText("No verifications found")).toBeNull();
  });

  it("counts a failed verification, not a passed one, for a signed manifest", async () => {
    api.state = { data: { manifests: [manifest("m-2", "host-failed")] }, isLoading: false, error: null };
    render(<VerifyPage />);

    await waitFor(() => expect(statValue("Failed")).toBe("1"));
    expect(within(rowOf("Manifest host-failed")).getByText("Failed")).toBeTruthy();
    expect(statValue("Passed")).toBe("0");
    expect(card("Passed")?.textContent).toContain("0.0% success rate");
  });

  it("shows invalid evidence, an unknown verdict and a failed call as unverified", async () => {
    verdicts["m-6"] = result("UNKNOWN");
    verdicts["m-7"] = { success: true, data: { status: { success: true, message: "" } } };
    api.state = {
      data: {
        manifests: [
          manifest("m-3", "host-invalid"),
          manifest("m-4", "host-rejected"),
          manifest("m-6", "host-unknown"),
          manifest("m-7", "host-no-result"),
        ],
      },
      isLoading: false,
      error: null,
    };
    try {
      render(<VerifyPage />);

      await waitFor(() => expect(statValue("Unverified")).toBe("4"));
      for (const host of ["host-invalid", "host-rejected", "host-unknown", "host-no-result"]) {
        expect(within(rowOf(`Manifest ${host}`)).getByText("Unverified")).toBeTruthy();
      }
      expect(statValue("Passed")).toBe("0");
      expect(card("Passed")?.textContent).toContain("0.0% success rate");
    } finally {
      delete verdicts["m-6"];
      delete verdicts["m-7"];
    }
  });

  it("names the manifest and reports no PCR mismatch per row", () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    const row = within(rowOf("Manifest host-verified"));
    expect(row.getByText("Manifest host-verified")).toBeTruthy();
    const mismatches = row.getByText("0");
    expect(mismatches.className).toContain("text-green-600");
  });

  it("rounds the success rate to one decimal", async () => {
    api.state = {
      data: { manifests: manifestsFixture.manifests.slice(0, 3) },
      isLoading: false,
      error: null,
    };
    render(<VerifyPage />);

    await waitFor(() => expect(card("Passed")?.textContent).toContain("33.3% success rate"));
  });

  it("refetches on Refresh and offers Run Verification", () => {
    api.state = { data: manifestsFixture, isLoading: false, error: null };
    render(<VerifyPage />);

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: /Run Verification/ })).toBeTruthy();
  });
});
