"use client";

import { useMemo } from "react";
import { useAttestation } from "trusted-platform-sdk";
import type {
  ApiResponse,
  CollectContainerAttestationRequest,
  CollectContainerAttestationResponse,
  CollectHostAttestationRequest,
  CollectHostAttestationResponse,
  CollectVMAttestationRequest,
  CollectVMAttestationResponse,
} from "trusted-platform-sdk";

/**
 * The attestation collect operations for the host, a VM and a container
 * (#2038), forwarded to the SDK so the browser reaches POST
 * /api/v1/attestation/host, /vm/{id} and /container/{id}.
 */
export function useAttestationCollect() {
  const attestation = useAttestation();
  return useMemo(
    () => ({
      collectHost: (
        req: CollectHostAttestationRequest
      ): Promise<ApiResponse<CollectHostAttestationResponse>> =>
        attestation.collectHostAttestation(req),
      collectVM: (
        req: CollectVMAttestationRequest
      ): Promise<ApiResponse<CollectVMAttestationResponse>> =>
        attestation.collectVMAttestation(req),
      collectContainer: (
        req: CollectContainerAttestationRequest
      ): Promise<ApiResponse<CollectContainerAttestationResponse>> =>
        attestation.collectContainerAttestation(req),
    }),
    [attestation]
  );
}
