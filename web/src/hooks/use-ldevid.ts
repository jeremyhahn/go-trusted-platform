"use client";

/**
 * LDevID hook: CreateLDevID, `POST /api/v1/idevid/ldevid`
 * (pkg/webservice/v1/rest/idevid/handlers.go lines 218-233).
 *
 * Calls the SDK API client directly because the SDK IDevIDService has no
 * CreateLDevID method. `overwrite` replaces the key at the handle, so a
 * control that sets it must confirm first.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** The device key algorithms CreateLDevID accepts (proto DeviceKeyAlgorithm). */
export type LDevIDAlgorithm = "ECDSA_P256" | "ECDSA_P384" | "RSA_2048" | "RSA_3072";

/** The LDevID persistent handle, distinct from the IDevID and IAK handles. */
export const LDEVID_DEFAULT_HANDLE = 0x81010102;

export interface CreateLDevIDInput {
  commonName: string;
  organization?: string;
  algorithm?: LDevIDAlgorithm;
  handle?: number;
  profile?: string;
  validityDays?: number;
  overwrite?: boolean;
}

/** CreateLDevIDResponse (protojson; PEM fields are base64 bytes). */
export interface CreateLDevIDResult {
  status: { success: boolean; message: string };
  csrPem: string;
  certificatePem: string;
  certificate?: Record<string, unknown>;
}

/** `DEVICE_KEY_ALGORITHM_${alg}` */
export function ldevidAlgorithmProtoName(alg: LDevIDAlgorithm): string {
  return `DEVICE_KEY_ALGORITHM_${alg}`;
}

/**
 * The request body: template {commonName (trimmed), organization when set};
 * algorithm proto name (default ECDSA_P256); handle (default
 * LDEVID_DEFAULT_HANDLE); profile when non-empty; validityDays when > 0;
 * overwrite only when true.
 */
export function ldevidRequestBody(input: CreateLDevIDInput): Record<string, unknown> {
  const template: Record<string, unknown> = { commonName: input.commonName.trim() };
  if (input.organization) {
    template.organization = input.organization;
  }
  const body: Record<string, unknown> = {
    template,
    algorithm: ldevidAlgorithmProtoName(input.algorithm ?? "ECDSA_P256"),
    handle: input.handle ?? LDEVID_DEFAULT_HANDLE,
  };
  if (input.profile) {
    body.profile = input.profile;
  }
  if (input.validityDays !== undefined && input.validityDays > 0) {
    body.validityDays = input.validityDays;
  }
  if (input.overwrite === true) {
    body.overwrite = true;
  }
  return body;
}

/** base64 to UTF-8 text (atob + TextDecoder); "" for "". */
export function decodePem(b64: string): string {
  if (!b64) {
    return "";
  }
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

export function useLDevID() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      createLDevID: (input: CreateLDevIDInput) =>
        api.post<CreateLDevIDResult>("/v1/idevid/ldevid", ldevidRequestBody(input), {
          // A lost response must not replay the create: it would issue a
          // second key and certificate, or replace one on overwrite.
          retry: { enabled: false },
        }),
    };
  }, [client]);
}
