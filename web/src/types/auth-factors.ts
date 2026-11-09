/**
 * Auth factor types — canonical data model matching §5e of the
 * bootstrap-auth-architecture spec (go-qrdb AuthFactor model).
 */

export type AuthFactorType = "mtls" | "fido2" | "piv";

export interface AuthFactor {
  id: string;
  user_id: string;
  type: AuthFactorType;
  label: string;
  metadata: Record<string, string>;
  registered_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  created_by: "self" | "admin" | "ceremony";
}

export interface ListAuthFactorsResponse {
  factors: AuthFactor[];
  total: number;
}

export interface AddAuthFactorRequest {
  type: AuthFactorType;
  label: string;
  // mtls: PEM-encoded certificate (generated or uploaded)
  cert_pem?: string;
  // fido2: serialised PublicKeyCredential from navigator.credentials.create()
  webauthn_response?: unknown;
  // piv: cert PEM read from the card
  piv_cert_pem?: string;
  piv_slot?: string;
}

export interface AddAuthFactorResponse {
  factor: AuthFactor;
}

export interface RotateAuthFactorRequest {
  factor_id: string;
  cert_pem?: string;
  webauthn_response?: unknown;
  piv_cert_pem?: string;
  piv_slot?: string;
}

export interface RelabelAuthFactorRequest {
  factor_id: string;
  label: string;
}

export interface MFAPolicyRequest {
  tenant_id: string;
  require_multiple_factors: boolean;
  min_factor_count: number;
}

/** Body of POST /api/v1/users/{id}/factors/mtls/issue-cert. */
export interface IssueMTLSCertRequest {
  /** PKCS#10 CSR, PEM; its subject must be exactly CN=<user id>. */
  csr_pem: string;
}

export interface IssueMTLSCertResponse {
  cert_pem: string;
  chain_pem?: string;
}

/** Vendor badge resolved from AAGUID lookup or cert inference. */
export interface VendorBadge {
  name: string;
  icon_url?: string;
  aaguid?: string;
}

/** Well-known AAGUID → vendor name mapping (subset; full list from FIDO MDS). */
export const KNOWN_AAGUIDS: Record<string, string> = {
  "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series",
  "cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 NFC",
  "f8a011f3-8c0a-4d15-8006-17111f9edc7d": "Security Key by Yubico",
  "b92c3f9a-c014-4056-887f-140a2501163b": "Security Key 2 NFC",
  "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5Ci",
  "149a2021-8ef6-4133-96b8-81f8d5b7f1f5": "Solo Tap 2",
  "8876631b-d4a0-427f-5773-0ec71c9e0279": "Nitrokey FIDO2",
  "12ded745-4bed-47d4-abaa-e713f51d6393": "Nitrokey 3",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "ChromeOS (Google)",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
  "9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
  "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
};

/**
 * Resolve a vendor badge from a FIDO2 AAGUID.
 * Returns null if the AAGUID is unknown.
 */
export function vendorFromAAGUID(aaguid: string): VendorBadge | null {
  const name = KNOWN_AAGUIDS[aaguid.toLowerCase()];
  if (!name) return null;
  return { name, aaguid };
}

/**
 * Infer a vendor badge from a PIV certificate subject CN or serial.
 */
export function vendorFromPIVCert(subject: string, serial?: string): VendorBadge {
  const lc = subject.toLowerCase();
  if (lc.includes("yubico") || lc.includes("yubikey")) {
    return { name: "YubiKey PIV" };
  }
  if (lc.includes("nitrokey")) {
    return { name: "Nitrokey PIV" };
  }
  if (lc.includes("goldkey")) {
    return { name: "GoldKey PIV" };
  }
  // Generic fallback — show issuer CN
  return { name: subject || (serial ? `Card ${serial.slice(-6)}` : "PIV Card") };
}

/**
 * Resolve vendor badge for an AuthFactor.
 */
export function resolveVendorBadge(factor: AuthFactor): VendorBadge {
  switch (factor.type) {
    case "fido2": {
      const aaguid = factor.metadata["aaguid"] ?? "";
      const resolved = aaguid ? vendorFromAAGUID(aaguid) : null;
      return resolved ?? { name: factor.metadata["vendor"] ?? "FIDO2 Key" };
    }
    case "piv": {
      const subject = factor.metadata["cert_subject"] ?? "";
      const serial = factor.metadata["card_serial"] ?? "";
      return vendorFromPIVCert(subject, serial);
    }
    case "mtls": {
      const issuer = factor.metadata["issuer_cn"];
      return { name: issuer ? issuer : "Self-issued (mTLS)" };
    }
  }
}
