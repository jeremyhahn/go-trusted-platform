'use client';

import * as React from 'react';

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
  device?: string;
  region?: string;
  key_id?: string;
  pcr_banks?: string[];
  pcr_registers?: number[];
  capabilities?: Record<string, boolean>;
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

const BASE = '/api/v1/kms';

function seg(name: string): string {
  return encodeURIComponent(name);
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: 'include',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: unknown = undefined;
  if (text) {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  if (!res.ok) {
    const msg =
      (parsed as { message?: string; error?: string } | undefined)?.message ??
      (parsed as { error?: string } | undefined)?.error ??
      `HTTP ${res.status}`;
    throw new Error(msg);
  }
  const env = parsed as { payload?: T; data?: T } | undefined;
  return (env?.payload ?? env?.data ?? parsed) as T;
}

export interface UseKmsOpsResult {
  /** The last error of any operation, cleared when the next one starts. */
  error: string | null;
  /** True while an operation is in flight. */
  busy: boolean;
  importKey: (input: KmsImportKeyInput) => Promise<KmsImportKeyResult | null>;
  updateKeyStatus: (name: string, status: string, version?: number) => Promise<KmsKeyStatusResult | null>;
  getKeyVersions: (name: string) => Promise<KmsKeyVersion[] | null>;
  hash: (data: string, algorithm: string) => Promise<KmsHashResult | null>;
  hmac: (name: string, data: string) => Promise<string | null>;
  verifyHmac: (name: string, data: string, mac: string) => Promise<boolean | null>;
  generateRandom: (numBytes: number) => Promise<string | null>;
  generateDataKey: (keyId: string, keySize?: number) => Promise<KmsDataKeyResult | null>;
  generateWrappedDataKey: (wrappingKeyId: string, keySize?: number) => Promise<KmsWrappedDataKeyResult | null>;
  getBackendStatus: () => Promise<KmsBackendStatus | null>;
}

/**
 * useKmsOps drives the KMS operations that have a REST route but no page of
 * their own (#1734): key import, status and versions, hash, HMAC, random bytes, data keys and the backend status.
 *
 * The calls go straight to the REST routes, as useReportedGateways does,
 * because the SDK's KMSService is built from the gRPC surface and some of
 * its paths differ from the REST router.
 */
export function useKmsOps(): UseKmsOpsResult {
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
      importKey: (input) => run(() => call<KmsImportKeyResult>('POST', '/keys/import', input)),
      updateKeyStatus: (name, status, version) =>
        run(() =>
          call<KmsKeyStatusResult>('PUT', `/keys/${seg(name)}/status`, version ? { status, version } : { status })
        ),
      getKeyVersions: (name) =>
        run(async () => {
          const res = await call<{ versions?: KmsKeyVersion[] }>('GET', `/keys/${seg(name)}/versions`);
          return res?.versions ?? [];
        }),
      hash: (data, algorithm) =>
        run(() => call<KmsHashResult>('POST', '/hash', { data: textToBase64(data), hash: algorithm })),
      hmac: (name, data) =>
        run(async () => {
          const res = await call<{ hmac: string }>('POST', `/hmac/${seg(name)}`, { data: textToBase64(data) });
          return res.hmac;
        }),
      verifyHmac: (name, data, mac) =>
        run(async () => {
          const res = await call<{ valid: boolean }>('POST', `/hmac/${seg(name)}/verify`, {
            data: textToBase64(data),
            hmac: mac,
          });
          return res.valid;
        }),
      generateRandom: (numBytes) =>
        run(async () => {
          const res = await call<{ bytes: string }>('POST', '/random', { num_bytes: numBytes });
          return res.bytes;
        }),
      generateDataKey: (keyId, keySize) =>
        run(() =>
          call<KmsDataKeyResult>('POST', '/data-keys', keySize ? { key_id: keyId, key_size: keySize } : { key_id: keyId })
        ),
      generateWrappedDataKey: (wrappingKeyId, keySize) =>
        run(() =>
          call<KmsWrappedDataKeyResult>(
            'POST',
            '/data-keys/wrapped',
            keySize ? { wrapping_key_id: wrappingKeyId, key_size: keySize } : { wrapping_key_id: wrappingKeyId }
          )
        ),
      getBackendStatus: () => run(() => call<KmsBackendStatus>('GET', '/backend/status')),
    }),
    [error, busy, run]
  );
}
