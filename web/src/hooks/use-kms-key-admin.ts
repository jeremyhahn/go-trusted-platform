'use client';

/**
 * useKmsKeyAdmin — a KMS key's status (UpdateKeyStatus) and the import of key
 * material as a new key (ImportKey).
 *
 * Both are reached on the SDK API client at the served `/v1/kms/keys` routes
 * (PUT /v1/kms/keys/{name}/status, POST /v1/kms/keys/import) until the SDK
 * KMSService matches them: its updateKeyStatus sends PATCH and its
 * ImportKeyRequest is camelCase (#2057).
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

/** The statuses an operator sets; DELETED and ROTATING are set elsewhere */
export const KEY_STATUSES = ['ENABLED', 'DISABLED', 'PENDING_DELETION', 'COMPROMISED'] as const;
export type KeyStatus = (typeof KEY_STATUSES)[number];

/** The algorithms the server's ImportKey accepts */
export const IMPORT_ALGORITHMS = [
  'AES-256-GCM',
  'CHACHA20-POLY1305',
  'RSA-2048',
  'RSA-4096',
  'ECDSA-P256',
  'ECDSA-P384',
  'ED25519',
] as const;

export interface KeyStatusResult {
  key_id?: string;
  version?: number;
  status?: string;
}

export interface ImportKeyInput {
  name: string;
  algorithm: string;
  /** Base64 key material, as the server's []byte field reads it */
  key_material: string;
  description?: string;
  wrapping_key_id?: string;
  usage?: string[];
}

export interface ImportKeyResult {
  key_id?: string;
  version?: number;
  algorithm?: string;
}

export function useKmsKeyAdmin() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      setStatus: (name: string, status: KeyStatus, version?: number) =>
        api.put<KeyStatusResult>(
          `/v1/kms/keys/${encodeURIComponent(name)}/status`,
          version ? { status, version } : { status }
        ),
      importKey: (input: ImportKeyInput) => api.post<ImportKeyResult>('/v1/kms/keys/import', input),
    };
  }, [client]);
}
