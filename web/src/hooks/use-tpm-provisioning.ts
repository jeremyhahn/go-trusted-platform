"use client";

/**
 * TPM provisioning hook (#2068): Provision, Clear, GetCapabilities and
 * GetPlatformAttributes.
 *
 * Provision and Clear go through `client.tpm`. GetCapabilities and
 * GetPlatformAttributes are `GET /api/v1/tpm/capabilities` and
 * `GET /api/v1/tpm/platform` on the SDK API client, because the SDK on main
 * has no method for them yet.
 *
 * Clear destroys every key in the TPM's storage and endorsement hierarchies;
 * callers put it behind a confirm.
 */

import { useMemo } from "react";
import { usePlatformClient, useTPM, type TPMProvisionRequest } from "trusted-platform-sdk";

/** A persistent TPM key: its handle and algorithm (protojson TPMKeyRef). */
export interface TPMKeyRef {
  handle?: number;
  algorithm?: string;
}

/** What the TPM supports (protojson TPMCapabilitiesResponse). */
export interface TPMCapabilities {
  algorithms?: string[];
  commands?: string[];
  eccCurves?: string[];
}

/** The TPM's platform attributes (protojson TPMPlatformAttributesResponse). */
export interface TPMPlatformAttributes {
  device?: string;
  isFips?: boolean;
  pcrExtended?: boolean;
  canSeal?: boolean;
  isSimulator?: boolean;
  manufacturer?: string;
  ek?: TPMKeyRef;
  srk?: TPMKeyRef;
  iak?: TPMKeyRef;
}

/** "0x81010001 (RSA)"; "not provisioned" when ref or its handle is missing. */
export function tpmKeyRefLabel(ref?: TPMKeyRef): string {
  if (ref?.handle === undefined || ref.handle === null) {
    return "not provisioned";
  }
  const hex = "0x" + (ref.handle >>> 0).toString(16).toUpperCase().padStart(8, "0");
  return ref.algorithm ? `${hex} (${ref.algorithm})` : hex;
}

/** Only the non-empty passwords and the three create flags. */
export function provisionRequest(o: { ownerPassword: string }): TPMProvisionRequest {
  // The daemon reads only the owner password; it always creates the EK and
  // SRK and never an AK, so nothing else is sent.
  return o.ownerPassword ? { ownerPassword: o.ownerPassword } : {};
}

export function useTPMProvisioning() {
  const client = usePlatformClient();
  const tpm = useTPM();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      getCapabilities: () => api.get<TPMCapabilities>("/v1/tpm/capabilities"),
      getPlatformAttributes: () => api.get<TPMPlatformAttributes>("/v1/tpm/platform"),
      provision: (req: TPMProvisionRequest) => tpm.provision(req),
      clear: (ownerPassword: string) => tpm.clear({ ownerPassword, confirm: true }),
    };
  }, [client, tpm]);
}
