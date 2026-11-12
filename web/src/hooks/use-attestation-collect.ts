"use client";

import * as React from "react";
import { useAttestation } from "trusted-platform-sdk";
import type { ApiResponse, VerifyManifestRequest } from "trusted-platform-sdk";

/** One attestation operation the collect page can run (#1732). */
export type AttestationCollectOperation =
  | "collectHost"
  | "collectVM"
  | "collectContainer"
  | "verifyManifest"
  | "deleteManifest";

export interface AttestationCollectState {
  /** Operation currently in flight, if any. */
  pending?: AttestationCollectOperation;
  /** Operation whose outcome `result` or `error` holds. */
  operation?: AttestationCollectOperation;
  result?: unknown;
  error?: string;
}

export interface UseAttestationCollectResult extends AttestationCollectState {
  collectHost: () => Promise<boolean>;
  collectVM: (vmId: string) => Promise<boolean>;
  collectContainer: (containerId: string) => Promise<boolean>;
  verifyManifest: (request: VerifyManifestRequest) => Promise<boolean>;
  deleteManifest: (id: string) => Promise<boolean>;
}

/** A fresh 32-byte anti-replay nonce, base64-encoded. */
export function newAttestationNonce(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  let raw = "";
  bytes.forEach((b) => {
    raw += String.fromCharCode(b);
  });
  return btoa(raw);
}

/**
 * The attestation collect, manifest verify and manifest delete operations,
 * with the outcome of the last one run.
 */
export function useAttestationCollect(): UseAttestationCollectResult {
  const attestation = useAttestation();
  const [state, setState] = React.useState<AttestationCollectState>({});

  const run = React.useCallback(
    async <T,>(
      operation: AttestationCollectOperation,
      call: () => Promise<ApiResponse<T>>
    ): Promise<boolean> => {
      setState((prev) => ({ ...prev, pending: operation }));
      try {
        const response = await call();
        if (!response.success) {
          setState({
            operation,
            error: response.error?.message ?? "The request failed",
          });
          return false;
        }
        setState({ operation, result: response.data ?? {} });
        return true;
      } catch (err) {
        setState({
          operation,
          error: err instanceof Error ? err.message : String(err),
        });
        return false;
      }
    },
    []
  );

  return {
    ...state,
    collectHost: () =>
      run("collectHost", () =>
        attestation.collectHostAttestation({ config: {}, nonce: newAttestationNonce() })
      ),
    collectVM: (vmId) =>
      run("collectVM", () =>
        attestation.collectVMAttestation({ vmId, config: {}, nonce: newAttestationNonce() })
      ),
    collectContainer: (containerId) =>
      run("collectContainer", () => attestation.collectContainerAttestation({ containerId })),
    verifyManifest: (request) =>
      run("verifyManifest", () => attestation.verifyManifest(request)),
    deleteManifest: (id) => run("deleteManifest", () => attestation.deleteManifest(id)),
  };
}
