import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { AuthFactor, AuthFactorType } from "@/types/auth-factors";
import { VendorBadge } from "./vendor-badge";

// #1820: VendorBadge shows the vendor resolved from the factor's metadata.

function factor(type: AuthFactorType, metadata: Record<string, string> = {}): AuthFactor {
  return {
    id: "f",
    user_id: "user-7",
    type,
    label: "factor",
    metadata,
    registered_at: "2026-11-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    created_by: "self",
  };
}

function badgeText(f: AuthFactor): string | null {
  const { container } = render(<VendorBadge factor={f} />);
  const text = container.textContent;
  cleanup();
  return text;
}

describe("VendorBadge", () => {
  afterEach(() => {
    cleanup();
  });

  it("names a FIDO2 key from a known AAGUID, case-insensitively", () => {
    expect(badgeText(factor("fido2", { aaguid: "2fc0579f-8113-47ea-b116-bb5a8db9202a" }))).toBe(
      "YubiKey 5 Series"
    );
    expect(badgeText(factor("fido2", { aaguid: "12DED745-4BED-47D4-ABAA-E713F51D6393" }))).toBe(
      "Nitrokey 3"
    );
  });

  it("prefers the known AAGUID over a vendor hint", () => {
    expect(
      badgeText(
        factor("fido2", { aaguid: "08987058-cadc-4b81-b6e1-30de50dcbe96", vendor: "Acme" })
      )
    ).toBe("Windows Hello");
  });

  it("falls back to the vendor hint, then a generic name, for an unknown or missing AAGUID", () => {
    expect(badgeText(factor("fido2", { aaguid: "00000000-0000-0000-0000-000000000000", vendor: "Acme Key" }))).toBe(
      "Acme Key"
    );
    expect(badgeText(factor("fido2", { aaguid: "not-a-guid" }))).toBe("FIDO2 Key");
    expect(badgeText(factor("fido2", { aaguid: "" }))).toBe("FIDO2 Key");
    expect(badgeText(factor("fido2"))).toBe("FIDO2 Key");
  });

  it("names PIV card vendors from the cert subject", () => {
    expect(badgeText(factor("piv", { cert_subject: "CN=YubiKey PIV Attestation" }))).toBe("YubiKey PIV");
    expect(badgeText(factor("piv", { cert_subject: "O=Yubico" }))).toBe("YubiKey PIV");
    expect(badgeText(factor("piv", { cert_subject: "CN=NITROKEY" }))).toBe("Nitrokey PIV");
    expect(badgeText(factor("piv", { cert_subject: "CN=GoldKey Token" }))).toBe("GoldKey PIV");
  });

  it("falls back to the subject, the card serial tail, or a generic PIV name", () => {
    expect(badgeText(factor("piv", { cert_subject: "CN=Agency Card" }))).toBe("CN=Agency Card");
    expect(badgeText(factor("piv", { card_serial: "0011223344556677" }))).toBe("Card 556677");
    expect(badgeText(factor("piv", { card_serial: "42" }))).toBe("Card 42");
    expect(badgeText(factor("piv"))).toBe("PIV Card");
  });

  it("shows the mTLS issuer CN, or self-issued without one", () => {
    expect(badgeText(factor("mtls", { issuer_cn: "Platform CA" }))).toBe("Platform CA");
    expect(badgeText(factor("mtls", { issuer_cn: "" }))).toBe("Self-issued (mTLS)");
    expect(badgeText(factor("mtls"))).toBe("Self-issued (mTLS)");
  });

  it("passes the className through to the badge", () => {
    render(<VendorBadge factor={factor("mtls")} className="hidden sm:inline-flex" />);
    const badge = screen.getByText("Self-issued (mTLS)");
    expect(badge.className).toContain("hidden");
    expect(badge.className).toContain("sm:inline-flex");
  });
});
