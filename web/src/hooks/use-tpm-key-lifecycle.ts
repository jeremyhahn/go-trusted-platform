'use client';

/**
 * useTPMKeyLifecycle — the endorsement and storage root key lifecycle on the
 * SDK TPMService: CreateEK, DeleteEK, ImportEKCertificate, CreateSRK and
 * DeleteSRK (#2068). Each call answers the SDK's ApiResponse, so the caller
 * shows a refusal as the control plane worded it.
 */

import { useMemo } from 'react';
import { useTPM } from 'trusted-platform-sdk';
import type {
  CreateEKRequest,
  CreateSRKRequest,
  DeleteEKRequest,
  DeleteSRKRequest,
  ImportEKCertificateRequest,
} from 'trusted-platform-sdk';

export function useTPMKeyLifecycle() {
  const tpm = useTPM();
  return useMemo(
    () => ({
      createEK: (req: CreateEKRequest = {}) => tpm.createEK(req),
      deleteEK: (req: DeleteEKRequest) => tpm.deleteEK(req),
      importEKCertificate: (req: ImportEKCertificateRequest) => tpm.importEKCertificate(req),
      createSRK: (req: CreateSRKRequest = {}) => tpm.createSRK(req),
      deleteSRK: (req: DeleteSRKRequest) => tpm.deleteSRK(req),
    }),
    [tpm]
  );
}

/** "0x81010001" or "2164326401" -> 2164326401; "" -> undefined; anything else -> NaN. */
export function parseHandle(text: string): number | undefined {
  const t = text.trim();
  if (t === '') {
    return undefined;
  }
  if (/^0x[0-9a-f]+$/i.test(t)) {
    return parseInt(t.slice(2), 16);
  }
  if (/^[0-9]+$/.test(t)) {
    return parseInt(t, 10);
  }
  return NaN;
}
