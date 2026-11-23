'use client';

/**
 * TPM certify hook (#2068): Certify and DeleteAK.
 *
 * Both calls go through the SDK TPMService: Certify on POST /v1/tpm/certify,
 * DeleteAK on its own route. The server refuses DeleteAK for the IAK, the
 * device identity key, and the caller shows that refusal verbatim.
 */

import { useMemo } from 'react';
import { useTPM } from 'trusted-platform-sdk';
import type { DeleteAKRequest, TPMCertifyRequest, TPMCertifyResponse } from 'trusted-platform-sdk';

/** tpm.proto CertifyResponse in protojson (bytes as base64). */
export type TPMCertifyResult = TPMCertifyResponse;

/** tpm.proto CertifyRequest: the persistent handle of the key to certify. */
export type TPMCertifyInput = TPMCertifyRequest;

export function useTPMCertify() {
  const tpm = useTPM();
  return useMemo(
    () => ({
      certify: (input: TPMCertifyInput) => tpm.certify(input),
      deleteAK: (req: DeleteAKRequest) => tpm.deleteAK(req),
    }),
    [tpm],
  );
}
