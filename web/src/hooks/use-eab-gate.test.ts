import { describe, expect, it } from "vitest";
import { act, renderHook } from "@testing-library/react";
import { EAB_OPERATIONS, eabRouteMissing, useEABGate } from "./use-eab-gate";
import type { EABOperation } from "./use-eab-gate";

const ALL: EABOperation[] = [
  "CreateCredential",
  "GetCredential",
  "ListCredentials",
  "RevokeCredential",
  "ValidateCredential",
  "DeleteCredential",
  "GetCredentialByKeyID",
  "GetCredentialQRCode",
  "GetEnrollmentURL",
  "MarkCredentialUsed",
  "CleanupExpiredCredentials",
];

describe("EAB_OPERATIONS", () => {
  it("names the REST route of every EABService operation", () => {
    expect(Object.keys(EAB_OPERATIONS).sort()).toEqual([...ALL].sort());
    expect(EAB_OPERATIONS.MarkCredentialUsed.route).toBe("POST /credentials/{id}/used");
    expect(EAB_OPERATIONS.CleanupExpiredCredentials.route).toBe("POST /credentials/cleanup");
    expect(EAB_OPERATIONS.GetEnrollmentURL.route).toBe("GET /credentials/{id}/url");
  });
});

describe("eabRouteMissing", () => {
  it("is true only for a 404 or 501 answer", () => {
    expect(eabRouteMissing({ status: 404 })).toBe(true);
    expect(eabRouteMissing({ status: 501 })).toBe(true);
    expect(eabRouteMissing(Object.assign(new Error("x"), { status: 501 }))).toBe(true);
    expect(eabRouteMissing({ status: 400 })).toBe(false);
    expect(eabRouteMissing({ status: 500 })).toBe(false);
    expect(eabRouteMissing(new Error("network"))).toBe(false);
    expect(eabRouteMissing(null)).toBe(false);
  });
});

describe("useEABGate", () => {
  it("offers every operation until the server says otherwise", () => {
    const { result } = renderHook(() => useEABGate());
    for (const op of ALL) {
      expect(result.current.isAvailable(op)).toBe(true);
      expect(result.current.reason(op)).toBeNull();
    }
  });

  it("gates an operation off, with its route as the reason, when the server has no route", () => {
    const { result } = renderHook(() => useEABGate());
    let gated = false;
    act(() => {
      gated = result.current.report("MarkCredentialUsed", { status: 501, message: "unimplemented" });
    });
    expect(gated).toBe(true);
    expect(result.current.isAvailable("MarkCredentialUsed")).toBe(false);
    expect(result.current.reason("MarkCredentialUsed")).toContain("POST /credentials/{id}/used");
    expect(result.current.reason("MarkCredentialUsed")).toContain("501");
    expect(result.current.isAvailable("RevokeCredential")).toBe(true);
  });

  it("keeps an operation on for an ordinary failure", () => {
    const { result } = renderHook(() => useEABGate());
    let gated = true;
    act(() => {
      gated = result.current.report("ValidateCredential", { status: 400, message: "bad key" });
    });
    expect(gated).toBe(false);
    expect(result.current.isAvailable("ValidateCredential")).toBe(true);
    expect(result.current.reason("ValidateCredential")).toBeNull();
  });

  it("does not gate an ID or key route off on a 404: a missing credential is not a missing route", () => {
    const byId: EABOperation[] = [
      "GetCredential",
      "GetCredentialByKeyID",
      "RevokeCredential",
      "DeleteCredential",
      "GetCredentialQRCode",
      "GetEnrollmentURL",
      "MarkCredentialUsed",
    ];
    const { result } = renderHook(() => useEABGate());
    act(() => {
      for (const op of byId) result.current.report(op, { status: 404, message: "not found" });
    });
    for (const op of byId) expect(result.current.isAvailable(op)).toBe(true);
  });

  it("gates a collection route off on a 404", () => {
    const { result } = renderHook(() => useEABGate());
    act(() => {
      result.current.report("CleanupExpiredCredentials", { status: 404, message: "no route" });
    });
    expect(result.current.isAvailable("CleanupExpiredCredentials")).toBe(false);
    expect(result.current.reason("CleanupExpiredCredentials")).toContain("POST /credentials/cleanup");
  });

  it("honours an operation the caller gates off up front", () => {
    const { result } = renderHook(() =>
      useEABGate({ CleanupExpiredCredentials: "not offered by this server" })
    );
    expect(result.current.isAvailable("CleanupExpiredCredentials")).toBe(false);
    expect(result.current.reason("CleanupExpiredCredentials")).toBe("not offered by this server");
  });
});
