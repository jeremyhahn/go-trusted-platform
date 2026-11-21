import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2060: the zone page's DNSSEC card renders useDNSSEC's status and signs the
// zone through it (the hook is mocked here; its own test covers the SDK calls).

type Dnssec = {
  status: Record<string, unknown> | undefined;
  isLoading: boolean;
  error: { message: string } | undefined;
  signZone: ReturnType<typeof vi.fn>;
  isSigning: boolean;
};

const { dnssec, toast } = vi.hoisted(() => ({
  dnssec: {} as Dnssec,
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useDNSSEC: () => dnssec,
  useToast: () => ({ toast }),
}));

import { DNSSECStatusCard } from "./dnssec-status-card";

const unsigned = { enabled: true, zoneSigned: false, keys: [], dsRecords: [], algorithm: "", keySize: "" };
// The real server shape: GetDNSSECStatus fills only the DNSKEY and DS records;
// protojson emits algorithm and keySize as empty strings (#2165 Codex).
function b64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}
const p256Key = b64(Array.from({ length: 64 }, (_, i) => i + 1));
const signed = {
  enabled: true,
  zoneSigned: true,
  keys: [
    { name: "example.com.", flags: 257, protocol: 3, algorithm: 13, key: p256Key, ttl: 3600 },
    { name: "example.com.", flags: 256, protocol: 3, algorithm: 13, key: p256Key, ttl: 3600 },
  ],
  dsRecords: [{ keyTag: 12345, algorithm: 13, digestType: 2, digest: "ABCDEF" }],
  algorithm: "",
  keySize: "",
};

function signButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: /Sign Zone/ }) as HTMLButtonElement;
}

beforeEach(() => {
  dnssec.status = unsigned;
  dnssec.isLoading = false;
  dnssec.error = undefined;
  dnssec.signZone = vi.fn();
  dnssec.isSigning = false;
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("DNSSECStatusCard", () => {
  it("shows an unsigned zone with an enabled Sign Zone button", () => {
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(screen.getByText("Unsigned")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBeGreaterThan(0);
    expect(signButton().disabled).toBe(false);
  });

  it("shows a signed zone with its keys and DS records", () => {
    dnssec.status = signed;
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(screen.getByText("Signed")).toBeTruthy();
    expect(screen.getByText("ECDSAP256SHA256 (13)")).toBeTruthy();
    expect(screen.getByText("256")).toBeTruthy();
    expect(screen.getByText("2")).toBeTruthy();
    const ds = screen.getAllByTestId("ds-record");
    expect(ds).toHaveLength(1);
    expect(ds[0].textContent).toBe("12345 13 2 ABCDEF");
  });

  it("shows a dash when the server sends keys it cannot size", () => {
    dnssec.status = { ...signed, keys: signed.keys.map((k) => ({ ...k, key: "" })) };
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(screen.getByText("ECDSAP256SHA256 (13)")).toBeTruthy();
    expect(screen.getAllByText("—").length).toBe(1);
  });

  it("prefers algorithm and key size the server fills", () => {
    dnssec.status = { ...signed, algorithm: "ECDSAP384SHA384", keySize: "384" };
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(screen.getByText("ECDSAP384SHA384")).toBeTruthy();
    expect(screen.getByText("384")).toBeTruthy();
  });

  it("signs the zone, toasts and calls onSigned", async () => {
    dnssec.signZone.mockResolvedValue({ status: { success: true } });
    const onSigned = vi.fn();
    render(<DNSSECStatusCard zoneName="example.com." onSigned={onSigned} />);

    fireEvent.click(signButton());

    expect(dnssec.signZone).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Zone signed", variant: "success" }))
    );
    expect(onSigned).toHaveBeenCalledTimes(1);
  });

  it("toasts the refusal and does not call onSigned", async () => {
    dnssec.signZone.mockRejectedValue({ code: "INTERNAL", message: "signer offline" });
    const onSigned = vi.fn();
    render(<DNSSECStatusCard zoneName="example.com." onSigned={onSigned} />);

    fireEvent.click(signButton());

    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Failed to sign zone",
        description: "signer offline",
        variant: "destructive",
      })
    );
    expect(onSigned).not.toHaveBeenCalled();
  });

  it("disables signing when DNSSEC is not enabled", () => {
    dnssec.status = { ...unsigned, enabled: false };
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(signButton().disabled).toBe(true);
    expect(screen.getByText("DNSSEC is not enabled on this server")).toBeTruthy();
  });

  it("disables the button while signing", () => {
    dnssec.isSigning = true;
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(signButton().disabled).toBe(true);
  });

  it("shows the error and no button when the status cannot be read", () => {
    dnssec.status = undefined;
    dnssec.error = { message: "boom" };
    render(<DNSSECStatusCard zoneName="example.com." />);
    expect(screen.getByText("DNSSEC status unavailable: boom")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /Sign Zone/ })).toBeNull();
  });
});
