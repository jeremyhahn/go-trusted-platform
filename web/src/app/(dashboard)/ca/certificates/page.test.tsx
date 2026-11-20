import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { Certificate, IssueCertInput } from "@/types/security";
import CertificatesPage from "./page";

// The hooks, router, table and form are stubbed: the table exposes the
// mapped rows and one button per row action, the form one submit button.

type ApiState = {
  data: unknown;
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
};

type MutationOptions = {
  onSuccess?: (r: unknown) => void;
  onError?: (e: Error) => void;
};

const push = vi.fn();
const ca = {
  listCertificates: vi.fn(),
  issueCertificate: vi.fn(),
  revokeCertificate: vi.fn(),
  renewCertificate: vi.fn(),
  downloadCertificatePEM: vi.fn(),
};
let apiState: ApiState;
let lastFetcher: (() => unknown) | undefined;
let tableRows: Certificate[] = [];
const formInput: { value: IssueCertInput } = {
  value: { subject: "CN=web,O=Acme", type: "leaf", validityDays: 30, keyAlgorithm: "ECDSA-P256" },
};

vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

vi.mock("@/hooks", () => ({
  useCA: () => ca,
  useToast: () => ({ toast: vi.fn() }),
  useApi: (fn: () => unknown) => {
    lastFetcher = fn;
    return apiState;
  },
  useMutation: <T,>(fn: (v: T) => Promise<unknown>, opts: MutationOptions) => ({
    isLoading: false,
    mutate: async (v: T) => {
      try {
        opts.onSuccess?.(await fn(v));
      } catch (e) {
        opts.onError?.(e as Error);
      }
    },
  }),
}));

vi.mock("@/components/features/ca/cert-table", () => ({
  CertTable: (props: {
    certificates: Certificate[];
    loading: boolean;
    onView: (c: Certificate) => void;
    onDownload: (c: Certificate) => void;
    onRevoke: (c: Certificate) => void;
    onRenew: (c: Certificate) => void;
  }) => {
    tableRows = props.certificates;
    return (
      <div>
        {props.loading ? <span>table loading</span> : null}
        {props.certificates.map((c) => (
          <div key={c.id}>
            <span>{c.subject}</span>
            <button onClick={() => props.onView(c)}>view {c.id}</button>
            <button onClick={() => props.onDownload(c)}>download {c.id}</button>
            <button onClick={() => props.onRevoke(c)}>revoke {c.id}</button>
            <button onClick={() => props.onRenew(c)}>renew {c.id}</button>
          </div>
        ))}
      </div>
    );
  },
}));

vi.mock("@/components/features/ca/issue-cert-form", () => ({
  IssueCertForm: ({ onSubmit }: { onSubmit: (d: IssueCertInput) => void }) => (
    <button onClick={() => onSubmit(formInput.value)}>submit issue</button>
  ),
}));

function state(over: Partial<ApiState> = {}): ApiState {
  return { data: null, isLoading: false, error: null, refetch: vi.fn(), ...over };
}

const root = { serial: "01", commonName: "Root CA", issuer: "Root CA", status: "active", notBefore: 0, notAfter: 86400 };
const inter = { serial: "02", common_name: "Issuing CA", issuer: "Root CA", status: "ACTIVE" };
const leaf = {
  serial: "03",
  subject: { common_name: "web.local" },
  issuer: "Issuing CA",
  status: "revoked",
  not_before: "2026-01-01T00:00:00Z",
  key_algorithm: "ECDSA-P256",
  signature_algorithm: "ECDSA-SHA256",
};

describe("CertificatesPage", () => {
  let alertSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    Object.values(ca).forEach((f) => f.mockReset());
    push.mockReset();
    apiState = state();
    lastFetcher = undefined;
    tableRows = [];
    alertSpy = vi.fn();
    vi.stubGlobal("alert", alertSpy);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("lists certificates through ca.listCertificates", () => {
    render(<CertificatesPage />);
    lastFetcher?.();
    expect(ca.listCertificates).toHaveBeenCalledTimes(1);
  });

  it("renders an empty table when the response has no certificates", () => {
    apiState = state({ data: {} });
    render(<CertificatesPage />);
    expect(tableRows).toEqual([]);
  });

  it("passes the loading state to the table and disables Refresh", () => {
    apiState = state({ isLoading: true });
    render(<CertificatesPage />);
    expect(screen.getByText("table loading")).toBeTruthy();
    expect((screen.getByRole("button", { name: /Refresh/ }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the fetch error", () => {
    apiState = state({ error: new Error("ca offline") });
    render(<CertificatesPage />);
    expect(screen.getByText("Error")).toBeTruthy();
    expect(screen.getByText("ca offline")).toBeTruthy();
  });

  it("maps both wire shapes and derives the certificate type", () => {
    apiState = state({ data: { certificates: [root, inter, leaf] } });
    render(<CertificatesPage />);
    const [r, i, l] = tableRows;
    expect(r).toMatchObject({
      id: "01",
      subject: "Root CA",
      type: "root",
      status: "active",
      notBefore: new Date(0).toISOString(),
      notAfter: new Date(86400 * 1000).toISOString(),
      publicKeyAlgorithm: "RSA",
      signatureAlgorithm: "",
    });
    expect(i).toMatchObject({ subject: "Issuing CA", type: "intermediate", status: "active", notBefore: "" });
    expect(l).toMatchObject({
      subject: "web.local",
      issuer: "Issuing CA",
      type: "leaf",
      status: "revoked",
      notBefore: "2026-01-01T00:00:00Z",
      publicKeyAlgorithm: "ECDSA-P256",
      signatureAlgorithm: "ECDSA-SHA256",
    });
  });

  it("prefers is_ca, falls back to Unknown and maps expired", () => {
    apiState = state({
      data: {
        certificates: [
          { serial: "10", commonName: "Sub", issuer: "Elsewhere", isCA: true },
          { serial: "11", status: "Expired" },
        ],
      },
    });
    render(<CertificatesPage />);
    expect(tableRows[0].type).toBe("intermediate");
    // no subject and no issuer: both read "Unknown", which counts as self-signed
    expect(tableRows[1]).toMatchObject({ subject: "Unknown", issuer: "Unknown", type: "root", status: "expired" });
  });

  it("refreshes on click", () => {
    const refetch = vi.fn();
    apiState = state({ refetch });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("navigates to the URL-encoded serial on view", () => {
    apiState = state({ data: { certificates: [{ serial: "a/b c", commonName: "x", issuer: "y" }] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("view a/b c"));
    expect(push).toHaveBeenCalledWith("/ca/certificates/a%2Fb%20c");
  });

  it("downloads the PEM under a sanitised file name", async () => {
    ca.downloadCertificatePEM.mockResolvedValue({ data: "PEM", error: null });
    const createObjectURL = vi.fn(() => "blob:cert");
    const revokeObjectURL = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { value: createObjectURL, configurable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: revokeObjectURL, configurable: true });
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("download 01"));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    expect(ca.downloadCertificatePEM).toHaveBeenCalledWith("01");
    expect((click.mock.contexts[0] as HTMLAnchorElement).download).toBe("Root_CA.pem");
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:cert");
  });

  it("alerts when the download returns an error or no data", async () => {
    ca.downloadCertificatePEM.mockResolvedValueOnce({ data: null, error: new Error("x") });
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("download 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to download certificate"));
  });

  it("alerts when the download throws", async () => {
    ca.downloadCertificatePEM.mockRejectedValueOnce(new Error("network"));
    vi.spyOn(console, "error").mockImplementation(() => {});
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("download 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to download certificate"));
  });

  it("does not revoke when the reason prompt is cancelled", () => {
    vi.stubGlobal("prompt", vi.fn(() => null));
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("revoke 01"));
    expect(ca.revokeCertificate).not.toHaveBeenCalled();
  });

  it("revokes with reason UNSPECIFIED and reloads", async () => {
    vi.stubGlobal("prompt", vi.fn(() => "key leaked"));
    ca.revokeCertificate.mockResolvedValue({});
    const refetch = vi.fn();
    apiState = state({ data: { certificates: [root] }, refetch });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("revoke 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Certificate revoked successfully"));
    expect(ca.revokeCertificate).toHaveBeenCalledWith({ serial: "01", reason: "UNSPECIFIED" });
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("alerts the revoke failure", async () => {
    vi.stubGlobal("prompt", vi.fn(() => "r"));
    ca.revokeCertificate.mockRejectedValue(new Error("denied"));
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("revoke 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to revoke certificate: denied"));
  });

  it("does not renew when the confirmation is declined", () => {
    vi.stubGlobal("confirm", vi.fn(() => false));
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("renew 01"));
    expect(ca.renewCertificate).not.toHaveBeenCalled();
  });

  it("renews on confirmation and alerts success or failure", async () => {
    const confirmSpy = vi.fn(() => true);
    vi.stubGlobal("confirm", confirmSpy);
    ca.renewCertificate.mockResolvedValueOnce({}).mockRejectedValueOnce(new Error("expired CA"));
    apiState = state({ data: { certificates: [root] } });
    render(<CertificatesPage />);
    fireEvent.click(screen.getByText("renew 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Certificate renewed successfully"));
    expect(confirmSpy).toHaveBeenCalledWith('Renew certificate for "Root CA"?');
    expect(ca.renewCertificate).toHaveBeenCalledWith({ serial: "01" });
    fireEvent.click(screen.getByText("renew 01"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to renew certificate: expired CA"));
  });

  it("issues a certificate with the parsed DN and wire algorithm", async () => {
    ca.issueCertificate.mockResolvedValue({});
    const refetch = vi.fn();
    apiState = state({ refetch });
    formInput.value = { subject: "CN=web, O=Acme ,OU=Ops,C=US,ST=CA,L=SF,STREET=1 Main,POSTALCODE=94000,X=ignored", type: "intermediate", validityDays: 30, keyAlgorithm: "ECDSA-P384" };
    render(<CertificatesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Issue Certificate/ }));
    fireEvent.click(await screen.findByText("submit issue"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Certificate issued successfully"));
    expect(ca.issueCertificate).toHaveBeenCalledWith({
      subject: {
        common_name: "web",
        organization: "Acme",
        organizational_unit: "Ops",
        country: "US",
        province: "CA",
        locality: "SF",
        address: "1 Main",
        postal_code: "94000",
      },
      valid_days: 30,
      key_algorithm: "ECDSA-P384",
      is_ca: true,
    });
    expect(refetch).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.queryByText("submit issue")).toBeNull());
  });

  it("defaults an invalid issue input: bare CN, 365 days, RSA-2048, leaf", async () => {
    ca.issueCertificate.mockResolvedValue({});
    formInput.value = {
      subject: "plain-name",
      type: "leaf",
      validityDays: 0,
      keyAlgorithm: "DSA-1024" as IssueCertInput["keyAlgorithm"],
    };
    render(<CertificatesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Issue Certificate/ }));
    fireEvent.click(await screen.findByText("submit issue"));
    await waitFor(() => expect(ca.issueCertificate).toHaveBeenCalled());
    expect(ca.issueCertificate).toHaveBeenCalledWith({
      subject: { common_name: "plain-name" },
      valid_days: 365,
      key_algorithm: "RSA-2048",
      is_ca: false,
    });
  });

  it("sends an empty subject for an empty DN and alerts the issue failure", async () => {
    ca.issueCertificate.mockRejectedValue(new Error("bad subject"));
    formInput.value = { subject: "", type: "root", validityDays: 10, keyAlgorithm: "RSA-4096" };
    render(<CertificatesPage />);
    fireEvent.click(screen.getByRole("button", { name: /Issue Certificate/ }));
    fireEvent.click(await screen.findByText("submit issue"));
    await waitFor(() => expect(alertSpy).toHaveBeenCalledWith("Failed to issue certificate: bad subject"));
    expect(ca.issueCertificate).toHaveBeenCalledWith(
      expect.objectContaining({ subject: {}, key_algorithm: "RSA-4096", is_ca: true })
    );
  });
});
