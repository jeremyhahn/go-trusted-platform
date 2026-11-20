"use client";

import * as React from "react";

/**
 * Capability gate for the EAB credential controls (#2050).
 *
 * Every EABService operation has a REST route. A control stays on until the
 * server shows it has no such route (501, or 404 on a route that names no
 * credential), then it is gated off with the route as the reason. Callers
 * may also gate an operation off up front, with their own reason.
 */
export type EABOperation =
  | "CreateCredential"
  | "GetCredential"
  | "ListCredentials"
  | "RevokeCredential"
  | "ValidateCredential"
  | "DeleteCredential"
  | "GetCredentialByKeyID"
  | "GetCredentialQRCode"
  | "GetEnrollmentURL"
  | "MarkCredentialUsed"
  | "CleanupExpiredCredentials";

export interface EABOperationInfo {
  /** REST route under /api/v1/eab. */
  route: string;
  /** True when the route names one credential (by ID or key ID). */
  addressed: boolean;
}

export const EAB_OPERATIONS: Record<EABOperation, EABOperationInfo> = {
  CreateCredential: { route: "POST /credentials", addressed: false },
  GetCredential: { route: "GET /credentials/{id}", addressed: true },
  ListCredentials: { route: "GET /credentials", addressed: false },
  RevokeCredential: { route: "POST /credentials/{id}/revoke", addressed: true },
  ValidateCredential: { route: "POST /credentials/validate", addressed: false },
  DeleteCredential: { route: "DELETE /credentials/{id}", addressed: true },
  GetCredentialByKeyID: { route: "GET /credentials/key/{key}", addressed: true },
  GetCredentialQRCode: { route: "GET /credentials/{id}/qrcode", addressed: true },
  GetEnrollmentURL: { route: "GET /credentials/{id}/url", addressed: true },
  MarkCredentialUsed: { route: "POST /credentials/{id}/used", addressed: true },
  CleanupExpiredCredentials: { route: "POST /credentials/cleanup", addressed: false },
};

function errorStatus(err: unknown): number | undefined {
  if (typeof err !== "object" || err === null || !("status" in err)) return undefined;
  const status = (err as { status?: unknown }).status;
  return typeof status === "number" ? status : undefined;
}

/** True when an error carries a 404 or 501 status, the answers of a missing route. */
export function eabRouteMissing(err: unknown): boolean {
  const status = errorStatus(err);
  return status === 404 || status === 501;
}

export type EABGateReasons = Partial<Record<EABOperation, string>>;

export interface UseEABGateResult {
  isAvailable: (op: EABOperation) => boolean;
  /** Why the operation is off, or null when it is on. */
  reason: (op: EABOperation) => string | null;
  /**
   * Report a failed call of `op`. Returns true when the failure shows the
   * server has no route for it, which gates the operation off.
   */
  report: (op: EABOperation, err: unknown) => boolean;
}

export function useEABGate(initial: EABGateReasons = {}): UseEABGateResult {
  const [reasons, setReasons] = React.useState<EABGateReasons>(() => ({ ...initial }));

  const reason = React.useCallback((op: EABOperation) => reasons[op] ?? null, [reasons]);
  const isAvailable = React.useCallback((op: EABOperation) => reasons[op] === undefined, [reasons]);

  const report = React.useCallback((op: EABOperation, err: unknown) => {
    const status = errorStatus(err);
    const info = EAB_OPERATIONS[op];
    const missing = status === 501 || (status === 404 && !info.addressed);
    if (!missing) return false;
    const text = `The server does not offer ${info.route} (HTTP ${status})`;
    setReasons((prev) => (prev[op] === text ? prev : { ...prev, [op]: text }));
    return true;
  }, []);

  return { isAvailable, reason, report };
}
