'use client';

import * as React from 'react';
import {
  usePlatformClient,
  type ApiResponse,
  type HashAlgorithm,
  type KeyStatus,
  type KMSKeyAlgorithm,
} from 'trusted-platform-sdk';

/**
 * Wire shapes of the KMS REST surface under /api/v1/kms (the Go router in
 * pkg/webservice/v1/rest/kms). Byte fields travel as base64 strings, the
 * encoding Go's encoding/json gives []byte.
 */
export interface KmsKeyVersion {
  version: number;
  status: string;
  algorithm: string;
  created_at?: string;
  disabled_at?: string;
}

export interface KmsBackendStatus {
  backend_type: string;
  status: string;
}

export interface KmsImportKeyInput {
  name: string;
  algorithm: string;
  /** base64 key material */
  key_material: string;
  wrapping_key_id?: string;
  description?: string;
}

export interface KmsImportKeyResult {
  key_id: string;
  version: number;
  algorithm: string;
}

export interface KmsKeyStatusResult {
  key_id: string;
  version: number;
  status: string;
}

/** Key statuses the v1 KMS router accepts on PUT /keys/{name}/status. */
export const KMS_KEY_STATUSES = [
  'ENABLED',
  'DISABLED',
  'PENDING_DELETION',
  'DELETED',
  'ROTATING',
  'COMPROMISED',
] as const;

export type KmsKeyStatus = (typeof KMS_KEY_STATUSES)[number];

export interface KmsHashResult {
  hash: string;
  digest: string;
}

export interface KmsDataKeyResult {
  key_id: string;
  plaintext_key: string;
  encrypted_key: string;
}

export interface KmsWrappedDataKeyResult {
  wrapping_key_id: string;
  wrapped_key: string;
}

/** Encodes UTF-8 text as base64, the JSON form of a Go []byte. */
export function textToBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

/** Decodes base64 to UTF-8 text. */
export function base64ToText(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

/** Unwraps an SDK response; a failed one becomes the thrown error. */
async function sdkData<T>(p: Promise<ApiResponse<T>>): Promise<T> {
  const res = await p;
  if (!res.success) {
    throw new Error(res.error?.message || 'KMS request failed');
  }
  return res.data as T;
}

export interface UseKmsOpsResult {
  /** The last error of any operation, cleared when the next one starts. */
  error: string | null;
  /** True while an operation is in flight. */
  busy: boolean;
  importKey: (input: KmsImportKeyInput) => Promise<KmsImportKeyResult | null>;
  updateKeyStatus: (name: string, status: KmsKeyStatus, version: number) => Promise<KmsKeyStatusResult | null>;
  getKeyVersions: (name: string) => Promise<KmsKeyVersion[] | null>;
  hash: (data: string, algorithm: string) => Promise<KmsHashResult | null>;
  hmac: (name: string, data: string, hash: string) => Promise<string | null>;
  verifyHmac: (name: string, data: string, mac: string, hash: string) => Promise<boolean | null>;
  generateRandom: (numBytes: number) => Promise<string | null>;
  generateDataKey: (keyId: string, algorithm: string, keySize: number) => Promise<KmsDataKeyResult | null>;
  generateWrappedDataKey: (wrappingKeyId: string, keyAlgorithm: string, keySize: number) => Promise<KmsWrappedDataKeyResult | null>;
  getBackendStatus: () => Promise<KmsBackendStatus | null>;
}

/**
 * useKmsOps drives the KMS operations that have a REST route but no page of
 * their own (#1734): key import, status and versions, hash, HMAC, random bytes, data keys and the backend status.
 *
 * The hook drives PlatformClient.kms, so the SDK's base URL, auth
 * interceptors and transport (HTTP or Wails) apply (#1675 F27).
 */
export function useKmsOps(): UseKmsOpsResult {
  const kms = usePlatformClient().kms;
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  const run = React.useCallback(async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    setBusy(true);
    setError(null);
    try {
      return await fn();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      return null;
    } finally {
      setBusy(false);
    }
  }, []);

  return React.useMemo<UseKmsOpsResult>(
    () => ({
      error,
      busy,
      importKey: (input) =>
        run(() =>
          sdkData(
            kms.importKey({
              name: input.name,
              keyMaterial: input.key_material,
              keySpec: { algorithm: input.algorithm as KMSKeyAlgorithm, usage: [] },
              ...(input.wrapping_key_id !== undefined ? { wrappingKeyId: input.wrapping_key_id } : {}),
              ...(input.description !== undefined ? { description: input.description } : {}),
            })
          )
        ),
      updateKeyStatus: (name, status, version) =>
        // The router accepts every KMS_KEY_STATUSES value; the SDK's KeyStatus
        // request type lists fewer, so the wire value is passed through.
        run(() => sdkData(kms.updateKeyStatus({ keyId: name, status: status as KeyStatus, version }))),
      getKeyVersions: (name) =>
        run(async () => {
          const res = await sdkData(kms.getKeyVersions({ keyId: name }));
          return res?.versions ?? [];
        }),
      hash: (data, algorithm) =>
        run(() => sdkData(kms.hash({ data: textToBase64(data), algorithm: algorithm as HashAlgorithm }))),
      hmac: (name, data, hash) =>
        run(async () => {
          const res = await sdkData(
            kms.hmac({ keyId: name, message: textToBase64(data), hashAlgorithm: hash as HashAlgorithm })
          );
          return res.hmac;
        }),
      verifyHmac: (name, data, mac, hash) =>
        run(async () => {
          const res = await sdkData(
            kms.verifyHMAC({
              keyId: name,
              message: textToBase64(data),
              hmac: mac,
              hashAlgorithm: hash as HashAlgorithm,
            })
          );
          return res.valid;
        }),
      generateRandom: (numBytes) =>
        run(async () => {
          const res = await sdkData(kms.generateRandom({ numBytes }));
          return res.bytes;
        }),
      generateDataKey: (keyId, algorithm, keySize) =>
        run(() =>
          sdkData(kms.generateDataKey({ keyId, algorithm: algorithm as KMSKeyAlgorithm, keySize }))
        ),
      generateWrappedDataKey: (wrappingKeyId, keyAlgorithm, keySize) =>
        run(() =>
          sdkData(
            kms.generateWrappedDataKey({
              wrappingKeyId,
              keyAlgorithm: keyAlgorithm as KMSKeyAlgorithm,
              keySize,
            })
          )
        ),
      getBackendStatus: () => run(() => sdkData(kms.getBackendStatus())),
    }),
    [error, busy, run, kms]
  );
}
