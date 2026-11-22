'use client';

/**
 * KMS digest hook: Hash, HMAC and VerifyHMAC (#2057).
 *
 * Hash, HMAC and VerifyHMAC are reached on the API client at the served
 * `/v1/kms` routes until the SDK KMSService matches them (#2057): its hmac
 * and verifyHMAC paths drop the key name and its request fields are
 * camelCase, while the server reads `data` and `hash`. Every `[]byte` field
 * travels as a base64 string in JSON.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

export type DigestAlgorithm = 'SHA-256' | 'SHA-384' | 'SHA-512';

export const DIGEST_ALGORITHMS: DigestAlgorithm[] = ['SHA-256', 'SHA-384', 'SHA-512'];

export interface KmsHashResult {
  hash?: string;
  digest?: string;
}

export interface KmsHmacResult {
  key_id?: string;
  hmac?: string;
}

export interface KmsHmacVerdict {
  valid?: boolean;
}

/** toBase64 encodes text as UTF-8, then base64, the JSON form of a Go []byte. */
export function toBase64(text: string): string {
  return btoa(Array.from(new TextEncoder().encode(text), (b) => String.fromCharCode(b)).join(''));
}

export function useKmsDigest() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    const key = (name: string) => `/v1/kms/hmac/${encodeURIComponent(name)}`;
    return {
      hash: (text: string, hash: DigestAlgorithm) =>
        api.post<KmsHashResult>('/v1/kms/hash', { data: toBase64(text), hash }),
      hmac: (name: string, text: string, hash: DigestAlgorithm) =>
        api.post<KmsHmacResult>(key(name), { data: toBase64(text), hash }),
      verifyHmac: (name: string, text: string, tag: string, hash: DigestAlgorithm) =>
        api.post<KmsHmacVerdict>(`${key(name)}/verify`, { data: toBase64(text), hmac: tag.trim(), hash }),
    };
  }, [client]);
}
