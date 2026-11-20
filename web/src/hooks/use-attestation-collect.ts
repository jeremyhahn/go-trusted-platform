"use client";

import * as React from "react";
import { useAttestation } from "trusted-platform-sdk";
import type { ApiResponse } from "trusted-platform-sdk";

/** One attestation operation the collect page can run (#1732). */
export type AttestationCollectOperation =
  | "collectHost"
  | "collectVM"
  | "collectContainer"
  | "deleteManifest";

export interface AttestationCollectState {
  /** Operation currently in flight, if any. */
  pending?: AttestationCollectOperation;
  /** Operation whose outcome `result` or `error` holds. */
  operation?: AttestationCollectOperation;
  result?: unknown;
  error?: string;
  /** True when the service answered that the operation is not available on this node. */
  unavailable?: boolean;
}

/**
 * VM and container collection always fail on the attestation service today:
 * it has no daemon-managed TPM session for workloads and answers
 * ErrTPMSessionNotConfigured (#1747 Codex round 2). The page gates both.
 */
export const WORKLOAD_COLLECTION_AVAILABLE: boolean = false;

export const WORKLOAD_COLLECTION_UNAVAILABLE =
  "VM and container attestation collection is not available yet: the attestation service has no daemon-managed TPM session for workloads.";

const TPM_SESSION_NOT_CONFIGURED = "requires a daemon-managed TPM session which is not configured";

export interface UseAttestationCollectResult extends AttestationCollectState {
  collectHost: () => Promise<boolean>;
  collectVM: (vmId: string) => Promise<boolean>;
  collectContainer: (containerId: string) => Promise<boolean>;
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
 * The attestation collect and manifest delete operations,
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
          const message = response.error?.message ?? "The request failed";
          const workload = operation === "collectVM" || operation === "collectContainer";
          if (workload && message.includes(TPM_SESSION_NOT_CONFIGURED)) {
            setState({ operation, unavailable: true, error: WORKLOAD_COLLECTION_UNAVAILABLE });
            return false;
          }
          setState({ operation, error: message });
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
    deleteManifest: (id) => run("deleteManifest", () => attestation.deleteManifest(id)),
  };
}
