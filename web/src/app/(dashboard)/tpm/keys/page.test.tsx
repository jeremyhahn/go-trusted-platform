import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import TPMKeysPage from "./page";

// #1824: the page lists the five TCG-prescribed keys from the TPM and IDevID
// services through the real useApi hook, and opens a detail dialog per key.

const tpm = {
  getEK: vi.fn(),
  getSRK: vi.fn(),
  getEKCertificate: vi.fn(),
};
const idevid = {
  getIAKInfo: vi.fn(),
  getIDevIDInfo: vi.fn(),
  getIAKCertificate: vi.fn(),
  getIDevIDCertificate: vi.fn(),
};
const toast = vi.fn();

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useIDevID: () => idevid,
  useToast: () => ({ toast }),
}));

const ekPub = "-----BEGIN PUBLIC KEY-----EK";
const derCert = "A".repeat(70);

function primaries() {
  tpm.getEK.mockResolvedValue({ data: { publicKey: ekPub, algorithm: "RSA_2048", handle: 0x81010001 } });
  tpm.getSRK.mockImplementation((req?: { handle?: number }) =>
    Promise.resolve(
      req?.handle === 0x81000002
        ? { data: { publicKey: "psrk-public-key-pem", algorithm: "ECC_P256", handle: 0x81000002 } }
        : { data: { publicKey: "ssrk-public-key-pem", algorithm: "RSA_2048", handle: 0x81000001 } }
    )
  );
}

function identities(iak: object = {}, idv: object = {}) {
  idevid.getIAKInfo.mockResolvedValue({
    data: {
      keyInfo: {
        handle: 0x81010002,
        algorithm: "ECDSA_P256",
        publicKeyPem: "iak-public-key-pem",
        createdAt: "2026-01-02T03:04:05Z",
        hasCertificate: true,
        ...iak,
      },
    },
  });
  idevid.getIDevIDInfo.mockResolvedValue({
    data: {
      keyInfo: {
        handle: 0x81020000,
        algorithm: "ECDSA_P256",
        publicKeyPem: "idevid-public-key-pem",
        hasCertificate: false,
        ...idv,
      },
    },
  });
}

function nothing() {
  tpm.getEK.mockRejectedValue(new Error("down"));
  tpm.getSRK.mockRejectedValue(new Error("down"));
  idevid.getIAKInfo.mockRejectedValue(new Error("down"));
  idevid.getIDevIDInfo.mockRejectedValue(new Error("down"));
}

/** The text of the stat card whose title is given (the cards come first). */
function card(title: string): string {
  return screen.getAllByText(title)[0]?.parentElement?.parentElement?.textContent ?? "";
}

/** Opens the row menu of the given key and picks the item. */
async function pick(row: number, item: RegExp) {
  const triggers = document.querySelectorAll('[aria-haspopup="menu"]');
  const trigger = triggers[row];
  if (!trigger) throw new Error(`no menu for row ${row}`);
  fireEvent.keyDown(trigger, { key: "Enter" });
  fireEvent.click(await screen.findByRole("menuitem", { name: item }));
}

// floating-ui probes every ancestor of an open menu with `matches(":modal")`,
// which jsdom answers by a document-wide `:fullscreen` scan (seconds of CPU).
// Nothing is ever modal in jsdom; answer the probe directly, as
// components/layout/account-identity.test.tsx does.
const nativeMatches = Element.prototype.matches;

describe("TPMKeysPage", () => {
  beforeAll(() => {
    Element.prototype.matches = function (this: Element, selector: string) {
      return selector === ":modal" ? false : nativeMatches.call(this, selector);
    };
  });

  afterAll(() => {
    Element.prototype.matches = nativeMatches;
  });

  beforeEach(() => {
    for (const fn of [...Object.values(tpm), ...Object.values(idevid)]) fn.mockReset();
    toast.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it("lists all five keys with their handles and counts them by type", async () => {
    primaries();
    identities();
    render(<TPMKeysPage />);

    expect(await screen.findByText("0x81010001")).toBeTruthy();
    for (const name of [
      "Endorsement Key",
      "Storage Root Key (SSRK)",
      "Platform Storage Root Key (PSRK)",
      "Initial Attestation Key (IAK)",
      "Initial Device Identifier (IDevID)",
    ]) {
      expect(screen.getAllByText(name).length).toBeGreaterThan(0);
    }
    for (const handle of ["0x81010001", "0x81000001", "0x81000002", "0x81010002", "0x81020000"]) {
      expect(screen.getByText(handle)).toBeTruthy();
    }
    expect(tpm.getSRK).toHaveBeenCalledWith({ handle: 0x81000002 });
    expect(card("Total Keys")).toContain("5");
    expect(card("Endorsement Key")).toContain("1");
    expect(card("Storage Root Key")).toContain("2");
    expect(card("Attestation Key")).toContain("1");
    expect(card("Device Identifier")).toContain("1");
    expect(screen.getByText(new Date("2026-01-02T03:04:05Z").toLocaleDateString())).toBeTruthy();
    expect(screen.getAllByText("—")).toHaveLength(4);
  });

  it("shows a dash for an unparseable creation date", async () => {
    nothing();
    identities({ createdAt: "not-a-date" });
    render(<TPMKeysPage />);

    expect((await screen.findAllByText("Initial Attestation Key (IAK)")).length).toBeGreaterThan(0);
    expect(screen.getAllByText("—")).toHaveLength(2);
  });

  it("skips keys without a public key or handle", async () => {
    tpm.getEK.mockResolvedValue({ data: { publicKey: "", handle: 0x81010001 } });
    tpm.getSRK.mockResolvedValue({ data: {} });
    idevid.getIAKInfo.mockResolvedValue({ data: { keyInfo: { handle: 0 } } });
    idevid.getIDevIDInfo.mockResolvedValue({ data: {} });
    render(<TPMKeysPage />);

    expect(await screen.findByText(/No TPM keys found/)).toBeTruthy();
    expect(card("Total Keys")).toContain("0");
  });

  it("shows the empty state when every fetch fails", async () => {
    nothing();
    render(<TPMKeysPage />);

    expect(await screen.findByText(/No TPM keys found/)).toBeTruthy();
    expect(screen.queryByText("Error")).toBeNull();
  });

  it("shows a server error response", async () => {
    nothing();
    tpm.getEK.mockResolvedValue({ error: { message: "ek unavailable" } });
    render(<TPMKeysPage />);

    expect(await screen.findByText("ek unavailable")).toBeTruthy();
  });

  it("opens the EK details and rewraps a DER certificate as PEM", async () => {
    primaries();
    identities();
    tpm.getEKCertificate.mockResolvedValue({ data: { certificate: derCert } });
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(0, /View Details/);

    const pem = await screen.findByText(/-----BEGIN CERTIFICATE-----/);
    expect(pem.textContent).toBe(
      ["-----BEGIN CERTIFICATE-----", "A".repeat(64), "A".repeat(6), "-----END CERTIFICATE-----"].join("\n")
    );
    expect(screen.getByText("manufacturer-issued")).toBeTruthy();
    expect(screen.getByRole("button", { name: /Copy PEM/ })).toBeTruthy();
    expect(idevid.getIAKCertificate).not.toHaveBeenCalled();
  });

  it("shows an IAK certificate that is already PEM as it is", async () => {
    primaries();
    identities();
    const pem = "-----BEGIN CERTIFICATE-----\nIAK\n-----END CERTIFICATE-----";
    idevid.getIAKCertificate.mockResolvedValue({ data: { certificate: { pem } } });
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(3, /View Details/);

    expect((await screen.findByText(/-----BEGIN CERTIFICATE-----/)).textContent).toBe(pem);
    expect(screen.getByText("present")).toBeTruthy();
  });

  it("explains an IDevID without a certificate", async () => {
    primaries();
    identities();
    idevid.getIDevIDCertificate.mockResolvedValue({ data: {} });
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(4, /View Details/);

    expect(await screen.findByText(/Use the Issue Certificate flow/)).toBeTruthy();
    expect(screen.getByText("not provisioned")).toBeTruthy();
  });

  it("fetches no certificate for a storage root key", async () => {
    primaries();
    identities();
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(1, /View Details/);

    expect(await screen.findByText(/Storage hierarchy primaries do not carry/)).toBeTruthy();
    expect(tpm.getEKCertificate).not.toHaveBeenCalled();
    expect(idevid.getIAKCertificate).not.toHaveBeenCalled();
    expect(idevid.getIDevIDCertificate).not.toHaveBeenCalled();
  });

  it("shows a certificate fetch failure in the dialog", async () => {
    primaries();
    identities();
    tpm.getEKCertificate.mockRejectedValue(new Error("nv read failed"));
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(0, /View Details/);

    expect(await screen.findByText("nv read failed")).toBeTruthy();
  });

  it("copies the public key and toasts", async () => {
    primaries();
    identities();
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    await pick(0, /Copy Public Key/);

    expect(writeText).toHaveBeenCalledWith(ekPub);
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Copied to clipboard", variant: "success" }));
  });

  it("fetches every key again on Refresh", async () => {
    primaries();
    identities();
    render(<TPMKeysPage />);
    await screen.findByText("0x81010001");

    fireEvent.click(screen.getByRole("button", { name: /Refresh/ }));

    await waitFor(() => expect(tpm.getEK).toHaveBeenCalledTimes(2));
    expect(tpm.getSRK).toHaveBeenCalledTimes(4);
    expect(idevid.getIAKInfo).toHaveBeenCalledTimes(2);
    expect(idevid.getIDevIDInfo).toHaveBeenCalledTimes(2);
  });
});
