import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import CABundlePage from "./page";

// The page reads the CA bundle through useApi(() => ca.getBundle()). These
// tests stub the hooks so each case controls the useApi state directly.

type ApiState = {
  data: unknown;
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
};

const toast = vi.fn();
const getBundle = vi.fn();
let apiState: ApiState;
let lastFetcher: (() => unknown) | undefined;

vi.mock("@/hooks", () => ({
  useCA: () => ({ getBundle }),
  useToast: () => ({ toast }),
  useApi: (fn: () => unknown) => {
    lastFetcher = fn;
    return apiState;
  },
}));

const CERT = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const TWO_CERTS = CERT + CERT;

function state(over: Partial<ApiState> = {}): ApiState {
  return { data: null, isLoading: false, error: null, refetch: vi.fn(), ...over };
}

describe("CABundlePage", () => {
  beforeEach(() => {
    toast.mockReset();
    getBundle.mockReset();
    apiState = state();
    lastFetcher = undefined;
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it("fetches the bundle through ca.getBundle", () => {
    render(<CABundlePage />);
    lastFetcher?.();
    expect(getBundle).toHaveBeenCalledTimes(1);
  });

  it("shows the loading state and disables the actions", () => {
    apiState = state({ isLoading: true });
    render(<CABundlePage />);
    expect(screen.getByText("Loading CA bundle...")).toBeTruthy();
    expect((screen.getByRole("button", { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /Copy PEM/ }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: /Download/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the error message when the fetch fails", () => {
    apiState = state({ error: new Error("bundle unavailable") });
    render(<CABundlePage />);
    expect(screen.getByText(/Failed to load CA bundle: bundle unavailable/)).toBeTruthy();
    expect(screen.queryByText("Loading CA bundle...")).toBeNull();
  });

  it("shows the empty state when there is no bundle", () => {
    render(<CABundlePage />);
    expect(screen.getByText("No CA bundle available.")).toBeTruthy();
    expect(screen.getByText("Platform CA bundle")).toBeTruthy();
  });

  it("shows the empty state for an object with no PEM field", () => {
    apiState = state({ data: { payload: { other: 1 } } });
    render(<CABundlePage />);
    expect(screen.getByText("No CA bundle available.")).toBeTruthy();
  });

  it("renders a flat PEM string and counts one certificate", () => {
    apiState = state({ data: CERT });
    render(<CABundlePage />);
    expect(screen.getByText("1 certificate in chain")).toBeTruthy();
    expect(screen.getByText(/BEGIN CERTIFICATE/)).toBeTruthy();
  });

  it("decodes a base64 PEM nested in payload.bundle.pem", () => {
    apiState = state({ data: { payload: { bundle: { pem: btoa(TWO_CERTS) } } } });
    render(<CABundlePage />);
    expect(screen.getByText("2 certificates in chain")).toBeTruthy();
  });

  it("reads pemData and a string bundle", () => {
    apiState = state({ data: { pemData: CERT } });
    const { unmount } = render(<CABundlePage />);
    expect(screen.getByText("1 certificate in chain")).toBeTruthy();
    unmount();

    apiState = state({ data: { bundle: btoa(TWO_CERTS) } });
    render(<CABundlePage />);
    expect(screen.getByText("2 certificates in chain")).toBeTruthy();
  });

  it("falls back to the raw string when it is neither PEM nor base64", () => {
    apiState = state({ data: { pem: "not base64 !!" } });
    render(<CABundlePage />);
    expect(screen.getByText("not base64 !!")).toBeTruthy();
    expect(screen.getByText("Platform CA bundle")).toBeTruthy();
  });

  it("calls refetch when Refresh is clicked", () => {
    const refetch = vi.fn();
    apiState = state({ data: CERT, refetch });
    render(<CABundlePage />);
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("copies the PEM and toasts success", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    apiState = state({ data: CERT });
    render(<CABundlePage />);
    fireEvent.click(screen.getByRole("button", { name: /Copy PEM/ }));
    await waitFor(() => expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Copied" })));
    expect(writeText).toHaveBeenCalledWith(CERT);
  });

  it("toasts a destructive error when the clipboard is refused", async () => {
    const writeText = vi.fn().mockRejectedValue(new Error("denied"));
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    apiState = state({ data: CERT });
    render(<CABundlePage />);
    fireEvent.click(screen.getByRole("button", { name: /Copy PEM/ }));
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(
        expect.objectContaining({ title: "Copy failed", variant: "destructive" })
      )
    );
  });

  it("downloads the PEM as ca-bundle.pem", () => {
    const createObjectURL = vi.fn(() => "blob:bundle");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { value: createObjectURL, configurable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: revokeObjectURL, configurable: true });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    apiState = state({ data: CERT });
    render(<CABundlePage />);
    fireEvent.click(screen.getByRole("button", { name: /Download/ }));
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe("ca-bundle.pem");
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:bundle");
  });
});
