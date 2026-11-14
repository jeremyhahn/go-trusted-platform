import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import React from "react";

import type { AuthFactor } from "@/types/auth-factors";
import { VendorBadge } from "./vendor-badge";

function factor(overrides: Partial<AuthFactor>): AuthFactor {
  return {
    id: "f1",
    user_id: "u1",
    type: "mtls",
    label: "laptop",
    metadata: {},
    registered_at: "2026-01-01T00:00:00Z",
    last_used_at: null,
    revoked_at: null,
    created_by: "self",
    ...overrides,
  };
}

describe("VendorBadge", () => {
  afterEach(() => {
    cleanup();
  });

  it("names a known FIDO2 AAGUID", () => {
    render(
      <VendorBadge
        factor={factor({
          type: "fido2",
          metadata: { aaguid: "cb69481e-8ff7-4039-93ec-0a2729a154a8" },
        })}
      />,
    );
    expect(screen.getByText("YubiKey 5 NFC")).toBeTruthy();
  });

  it("matches a known AAGUID case-insensitively", () => {
    render(
      <VendorBadge
        factor={factor({
          type: "fido2",
          metadata: { aaguid: "CB69481E-8FF7-4039-93EC-0A2729A154A8" },
        })}
      />,
    );
    expect(screen.getByText("YubiKey 5 NFC")).toBeTruthy();
  });

  it("falls back to the vendor metadata for an unknown AAGUID", () => {
    render(
      <VendorBadge
        factor={factor({
          type: "fido2",
          metadata: { aaguid: "00000000-0000-0000-0000-000000000000", vendor: "Acme Key" },
        })}
      />,
    );
    expect(screen.getByText("Acme Key")).toBeTruthy();
  });

  it("falls back to FIDO2 Key with no metadata", () => {
    render(<VendorBadge factor={factor({ type: "fido2" })} />);
    expect(screen.getByText("FIDO2 Key")).toBeTruthy();
  });

  it("names a YubiKey PIV card from the subject", () => {
    render(
      <VendorBadge
        factor={factor({ type: "piv", metadata: { cert_subject: "CN=Yubico PIV Attestation" } })}
      />,
    );
    expect(screen.getByText("YubiKey PIV")).toBeTruthy();
  });

  it("shows the PIV card serial tail when there is no subject", () => {
    render(
      <VendorBadge factor={factor({ type: "piv", metadata: { card_serial: "0123456789" } })} />,
    );
    expect(screen.getByText("Card 456789")).toBeTruthy();
  });

  it("shows PIV Card with no metadata", () => {
    render(<VendorBadge factor={factor({ type: "piv" })} />);
    expect(screen.getByText("PIV Card")).toBeTruthy();
  });

  it("shows the mTLS issuer CN", () => {
    render(
      <VendorBadge factor={factor({ type: "mtls", metadata: { issuer_cn: "Platform CA" } })} />,
    );
    expect(screen.getByText("Platform CA")).toBeTruthy();
  });

  it("shows Self-issued for an mTLS factor with an empty issuer", () => {
    render(<VendorBadge factor={factor({ type: "mtls", metadata: { issuer_cn: "" } })} />);
    expect(screen.getByText("Self-issued (mTLS)")).toBeTruthy();
  });

  it("passes the className through to the badge", () => {
    render(<VendorBadge factor={factor({ type: "mtls" })} className="extra-class" />);
    expect(screen.getByText("Self-issued (mTLS)").className).toContain("extra-class");
  });
});
