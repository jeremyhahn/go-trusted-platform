'use client';

/**
 * TPM certify hook (#2068): Certify and DeleteAK.
 *
 * Certify goes through the platform's API client on POST /v1/tpm/certify
 * until the SDK has a certify call; DeleteAK goes through the SDK TPMService.
 * The server refuses DeleteAK for the IAK, the device identity key, and the
 * caller shows that refusal verbatim.
 */

import { useMemo } from 'react';
import { usePlatformClient, useTPM } from 'trusted-platform-sdk';
import type { DeleteAKRequest } from 'trusted-platform-sdk';

/** tpm.proto CertifyResponse in protojson (bytes as base64). */
export interface TPMCertifyResult {
  certifyInfo?: string;
  signature?: string;
  signatureAlgorithm?: string;
  certifyInfoSignature?: string;
  attestingKeyPublic?: string;
  attestedKeyPublic?: string;
  attestingKeyPublicArea?: string;
  attestedKeyPublicArea?: string;
  nonce?: string;
}

/** tpm.proto CertifyRequest: the persistent handle of the key to certify. */
export interface TPMCertifyInput {
  keyHandle: number;
  keyPassword?: string;
  /** base64 */
  nonce?: string;
}

export function useTPMCertify() {
  const client = usePlatformClient();
  const tpm = useTPM();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      certify: (input: TPMCertifyInput) => api.post<TPMCertifyResult>('/v1/tpm/certify', input),
      deleteAK: (req: DeleteAKRequest) => tpm.deleteAK(req),
    };
  }, [client, tpm]);
}
