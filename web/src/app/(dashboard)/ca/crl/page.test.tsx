import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import CRLPage from "./page";

// The page reads the CRL through useApi(() => ca.getCRL()). The hooks are
// stubbed so each case sets the useApi state directly.

type ApiState = {
  data: unknown;
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
};

const toast = vi.fn();
const getCRL = vi.fn();
let apiState: ApiState;
let lastFetcher: (() => unknown) | undefined;

vi.mock("@/hooks", () => ({
  useCA: () => ({ getCRL }),
  useToast: () => ({ toast }),
  useApi: (fn: () => unknown) => {
    lastFetcher = fn;
    return apiState;
  },
}));

function state(over: Partial<ApiState> = {}): ApiState {
  return { data: null, isLoading: false, error: null, refetch: vi.fn(), ...over };
}

// 72 base64 characters (52 bytes), so the PEM body wraps once at 64.
const DATA = btoa("x".repeat(51)) + "AA==";

function stubDownload() {
  const blobs: Blob[] = [];
  const createObjectURL = vi.fn((b: Blob) => {
    blobs.push(b);
    return "blob:crl";
  });
  const revokeObjectURL = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { value: createObjectURL, configurable: true });
  Object.defineProperty(URL, "revokeObjectURL", { value: revokeObjectURL, configurable: true });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  return { blobs, click, revokeObjectURL };
}

describe("CRLPage", () => {
  beforeEach(() => {
    toast.mockReset();
    getCRL.mockReset();
    apiState = state();
    lastFetcher = undefined;
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("fetches the CRL through ca.getCRL", () => {
    render(<CRLPage />);
    lastFetcher?.();
    expect(getCRL).toHaveBeenCalledTimes(1);
  });

  it("shows the loading state while no CRL is held", () => {
    apiState = state({ isLoading: true });
    render(<CRLPage />);
    expect(screen.getByText("Loading CRL...")).toBeTruthy();
    expect((screen.getByRole("button", { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("keeps showing the held CRL while it reloads", () => {
    apiState = state({ isLoading: true, data: { crl: { revokedCount: 0 } } });
    render(<CRLPage />);
    expect(screen.queryByText("Loading CRL...")).toBeNull();
    expect(screen.getByText("Validity")).toBeTruthy();
  });

  it("shows the fetch error", () => {
    apiState = state({ error: new Error("crl unavailable") });
    render(<CRLPage />);
    expect(screen.getByText("Failed to load CRL: crl unavailable")).toBeTruthy();
  });

  it("shows placeholders and disables the downloads with no CRL", () => {
    apiState = state({ data: { other: true } });
    render(<CRLPage />);
    expect(screen.getAllByText("—")).toHaveLength(2);
    expect(screen.getByText("0")).toBeTruthy();
    expect(screen.getByText("No certificates have been revoked.")).toBeTruthy();
    expect((screen.getByRole("button", { name: /Download PEM/ }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /Download DER/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("reads the camelCase CRL and lists the revoked certificates", () => {
    const t = "2026-11-01T00:00:00Z";
    apiState = state({
      data: {
        crl: {
          data: DATA,
          lastUpdate: t,
          nextUpdate: "not a date",
          revokedCerts: [
            { serial: "0A", reason: "KEY_COMPROMISE", revocationTime: t },
            { serial: "0B" },
          ],
        },
      },
    });
    render(<CRLPage />);
    expect(screen.getByText("2 certificates currently revoked.")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    expect(screen.getByText("0A")).toBeTruthy();
    expect(screen.getByText("KEY_COMPROMISE")).toBeTruthy();
    expect(screen.getAllByText(new Date(t).toLocaleString())).toHaveLength(2);
    // invalid next update, missing reason and missing revocation time
    expect(screen.getAllByText("—")).toHaveLength(3);
  });

  it("reads the snake_case CRL from the full envelope", () => {
    apiState = state({
      data: {
        payload: {
          crl: {
            last_update: "2026-11-01T00:00:00Z",
            revoked_count: 7,
            revoked_certs: [{ serial: "0C", reason: 1, revocation_time: "2026-11-02T00:00:00Z" }],
          },
        },
      },
    });
    render(<CRLPage />);
    expect(screen.getByText("1 certificate currently revoked.")).toBeTruthy();
    expect(screen.getByText("7")).toBeTruthy();
    expect(screen.getByText("1")).toBeTruthy();
  });

  it("refreshes on click", () => {
    const refetch = vi.fn();
    apiState = state({ refetch });
    render(<CRLPage />);
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("downloads the DER bytes as platform.crl", async () => {
    const { blobs, click, revokeObjectURL } = stubDownload();
    apiState = state({ data: { crl: { data: DATA } } });
    render(<CRLPage />);
    fireEvent.click(screen.getByRole("button", { name: /Download DER/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "CRL downloaded", description: "platform.crl" })
    );
    expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe("platform.crl");
    expect(blobs[0].type).toBe("application/pkix-crl");
    expect(blobs[0].size).toBe(atob(DATA).length);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:crl");
  });

  it("downloads a PEM wrapped at 64 columns", async () => {
    const { blobs, click } = stubDownload();
    apiState = state({ data: { crl: { data: DATA } } });
    render(<CRLPage />);
    fireEvent.click(screen.getByRole("button", { name: /Download PEM/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({ title: "CRL downloaded", description: "platform-crl.pem" })
    );
    expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe("platform-crl.pem");
    expect(blobs[0].type).toBe("application/x-pem-file");
    // jsdom's Blob has no text(): read it through FileReader.
    const text = await new Promise<string>((resolve) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.readAsText(blobs[0]);
    });
    expect(text).toBe(
      `-----BEGIN X509 CRL-----\n${DATA.slice(0, 64)}\n${DATA.slice(64)}\n-----END X509 CRL-----\n`
    );
  });

  it("toasts a destructive error when the CRL data is not base64", async () => {
    stubDownload();
    apiState = state({ data: { crl: { data: "%%% not base64 %%%" } } });
    render(<CRLPage />);
    fireEvent.click(screen.getByRole("button", { name: /Download DER/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Download failed", variant: "destructive" })
      )
    );
  });
});
