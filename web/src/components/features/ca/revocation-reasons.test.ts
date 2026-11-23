import { describe, it, expect } from "vitest";
import { REVOCATION_REASONS, isRevocationReason } from "./revocation-reasons";

describe("revocation reasons", () => {
  it("lists the ten RFC 5280 reasons in order", () => {
    expect([...REVOCATION_REASONS]).toEqual([
      "UNSPECIFIED",
      "KEY_COMPROMISE",
      "CA_COMPROMISE",
      "AFFILIATION_CHANGED",
      "SUPERSEDED",
      "CESSATION_OF_OPERATION",
      "CERTIFICATE_HOLD",
      "REMOVE_FROM_CRL",
      "PRIVILEGE_WITHDRAWN",
      "AA_COMPROMISE",
    ]);
  });

  it("accepts a listed reason and refuses anything else", () => {
    expect(isRevocationReason("KEY_COMPROMISE")).toBe(true);
    expect(isRevocationReason("key leaked")).toBe(false);
    expect(isRevocationReason("")).toBe(false);
  });
});
