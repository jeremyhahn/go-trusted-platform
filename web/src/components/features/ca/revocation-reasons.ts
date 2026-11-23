import type { RevocationReason } from "trusted-platform-sdk";

// The RFC 5280 CRLReason names of the SDK enum, spelled out once so every
// revoke prompt and its guard cannot drift.
export const REVOCATION_REASONS = [
  "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED",
  "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE",
] as const satisfies readonly RevocationReason[];

export function isRevocationReason(value: string): value is RevocationReason {
  return (REVOCATION_REASONS as readonly string[]).includes(value);
}
