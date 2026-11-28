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
import { usePlatformClient, type ApiResponse } from 'trusted-platform-sdk';

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
    return {
      hash: (text: string, hash: DigestAlgorithm) =>
        api.post<KmsHashResult>('/v1/kms/hash', { data: toBase64(text), hash }),
      // #2180 round 9: the backend makes a fresh MAC key per HMAC call, so a
      // tag it computes never verifies. Both calls are withheld, with no
      // request, until the backend uses a stable MAC key.
      hmac: (_name: string, _text: string, _hash: DigestAlgorithm): Promise<ApiResponse<KmsHmacResult>> =>
        Promise.resolve(hmacWithheld<KmsHmacResult>()),
      verifyHmac: (
        _name: string,
        _text: string,
        _tag: string,
        _hash: DigestAlgorithm,
      ): Promise<ApiResponse<KmsHmacVerdict>> => Promise.resolve(hmacWithheld<KmsHmacVerdict>()),
    };
  }, [client]);
}

/** Why the HMAC controls are withheld (#2180 round 9). */
export const HMAC_UNAVAILABLE = 'HMAC is not available until the backend uses a stable MAC key';

function hmacWithheld<T>(): ApiResponse<T> {
  return { success: false, error: { code: 'HMAC_UNAVAILABLE', status: 501, message: HMAC_UNAVAILABLE } };
}
