"use client";

import * as React from "react";
import { useTPM } from "trusted-platform-sdk";

/**
 * The TPM key lifecycle operations the TPM Keys page drives (#1735).
 */
export type TPMKeyOperation =
  | "provision"
  | "clear"
  | "capabilities"
  | "platform"
  | "createEK"
  | "importEKCertificate"
  | "deleteEK"
  | "createSRK"
  | "deleteSRK"
  | "createAK"
  | "getAK"
  | "deleteAK"
  | "quote"
  | "verifyQuote"
  | "certify";

/** The response shape every SDK call resolves to. */
export interface OperationResponse {
  success?: boolean;
  data?: unknown;
  error?: { message?: string } | string;
}

export type TPMClient = ReturnType<typeof useTPM>;

/** Reads the error message out of a failed response or a thrown value. */
export function operationError(value: unknown, fallback: string): string {
  if (value instanceof Error && value.message) return value.message;
  if (value && typeof value === "object" && "error" in value) {
    const err = (value as OperationResponse).error;
    if (typeof err === "string" && err) return err;
    if (err && typeof err === "object" && err.message) return err.message;
  }
  return fallback;
}

/**
 * useTPMKeyOperations runs one TPM operation at a time and keeps the
 * latest result and error of each, keyed by operation.
 */
export function useTPMKeyOperations() {
  const tpm = useTPM();
  const [pending, setPending] = React.useState<TPMKeyOperation | null>(null);
  const [results, setResults] = React.useState<Partial<Record<TPMKeyOperation, unknown>>>({});
  const [errors, setErrors] = React.useState<Partial<Record<TPMKeyOperation, string>>>({});

  const run = React.useCallback(
    async (op: TPMKeyOperation, call: (client: TPMClient) => Promise<OperationResponse>) => {
      setPending(op);
      setErrors((prev) => ({ ...prev, [op]: undefined }));
      try {
        const res = await call(tpm);
        if (res.success === false) {
          setErrors((prev) => ({ ...prev, [op]: operationError(res, `${op} failed`) }));
          return null;
        }
        setResults((prev) => ({ ...prev, [op]: res.data ?? {} }));
        return res.data ?? {};
      } catch (err) {
        setErrors((prev) => ({ ...prev, [op]: operationError(err, `${op} failed`) }));
        return null;
      } finally {
        setPending(null);
      }
    },
    [tpm],
  );

  return { tpm, pending, results, errors, run };
}
