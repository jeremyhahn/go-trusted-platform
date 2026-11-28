"use client";

/**
 * KMS data keys: GenerateDataKey and GenerateWrappedDataKey, served at
 * `POST /api/v1/kms/data-keys` and `POST /api/v1/kms/data-keys/wrapped`
 * (pkg/webservice/v1/rest/kms/handlers.go).
 *
 * The hook calls the SDK API client directly because the SDK KMS service's
 * data-key paths do not match the server. The server mints only its 256-bit
 * default, so no key size or algorithm is sent.
 *
 * The plaintext key is secret: a page shows it once and never stores or
 * logs it.
 */

import { useMemo } from "react";
import { usePlatformClient, type ApiResponse } from "trusted-platform-sdk";

/** GenerateDataKey answer; the keys are base64. */
export interface KMSDataKey {
  key_id: string;
  plaintext_key: string;
  encrypted_key: string;
}

/** GenerateWrappedDataKey answer; the wrapped key is base64. */
export interface KMSWrappedDataKey {
  wrapping_key_id: string;
  wrapped_key: string;
}

/** UTF-8 text to base64 (TextEncoder + btoa); undefined for "" or undefined (after trim). */
export function encryptionContext(text: string | undefined): string | undefined {
  const trimmed = text?.trim();
  if (!trimmed) {
    return undefined;
  }
  const bytes = new TextEncoder().encode(trimmed);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary);
}

/** Decoded byte length of a base64 string (atob(b64).length); 0 for "". */
export function base64ByteLength(b64: string): number {
  if (b64 === "") {
    return 0;
  }
  return atob(b64).length;
}

export function useKMSDataKeys() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      generateDataKey: (keyId: string, contextText?: string): Promise<ApiResponse<KMSDataKey>> =>
        encryptionContext(contextText)
          ? Promise.resolve(contextRefused())
          : api.post<KMSDataKey>("/v1/kms/data-keys", { key_id: keyId.trim() }),
      generateWrappedDataKey: (
        wrappingKeyId: string,
        contextText?: string,
      ): Promise<ApiResponse<KMSWrappedDataKey>> =>
        encryptionContext(contextText)
          ? Promise.resolve(contextRefused())
          : api.post<KMSWrappedDataKey>("/v1/kms/data-keys/wrapped", {
              wrapping_key_id: wrappingKeyId.trim(),
            }),
    };
  }, [client]);
}

/**
 * #2180 round 9: the pinned backend ignores the encryption/wrapping context,
 * so a key generated "under" one would unwrap without it. A nonempty context
 * is refused before any request rather than silently dropped.
 */
export const CONTEXT_UNSUPPORTED =
  "An encryption context is not supported: the KMS backend does not bind it to the key yet";

function contextRefused<T>(): ApiResponse<T> {
  return { success: false, error: { code: "CONTEXT_UNSUPPORTED", status: 400, message: CONTEXT_UNSUPPORTED } };
}
