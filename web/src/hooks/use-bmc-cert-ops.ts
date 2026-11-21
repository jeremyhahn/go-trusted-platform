"use client";

/**
 * BMC certificate hook: EnrollBMC, RestoreFactoryCert and
 * ReplaceWebCertificate on `/api/v1/bmc/{profileID}/enroll`,
 * `/cert/restore` and `PUT /cert` (pkg/webservice/v1/bmc enroll.go,
 * cert_restore.go, handler.go).
 *
 * It calls the SDK API client directly, as use-ntp.ts does, because the SDK
 * has no BMC service on main. Fields are snake_case and `device_id` is a
 * decimal string. Enroll always sends a JSON object because the server
 * refuses an empty body.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** Optional overrides for the enrolment ceremony. */
export interface BMCEnrollOptions {
  replace_certificate?: boolean;
  rotate_password?: boolean;
  dns_register?: boolean;
  dane_publish?: boolean;
}

/** One step of an enrol or restore ceremony. */
export interface BMCCeremonyStep {
  name: string;
  ok: boolean;
  detail?: string;
}

/** Certificate metadata the server records. */
export interface BMCCertMeta {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  spki_sha256: string;
  sha256: string;
  captured_at: string;
}

export interface BMCEnrollResult {
  device_id: string;
  endpoint: string;
  hostname: string;
  dns_name?: string;
  pin_spki_sha256: string;
  factory_cert_pem?: string;
  factory_cert_meta: BMCCertMeta;
  new_cert_pem?: string;
  ca_cert_pem?: string;
  steps: BMCCeremonyStep[];
}

export interface BMCRestoreResult {
  device_id: string;
  endpoint: string;
  hostname: string;
  new_cert_meta: BMCCertMeta;
  new_cert_pem?: string;
  steps: BMCCeremonyStep[];
}

export interface BMCReplaceCertRequest {
  cert_pem: string;
  key_pem: string;
}

/** The names of the steps that did not succeed, in order; [] for undefined. */
export function failedCeremonySteps(steps?: BMCCeremonyStep[]): string[] {
  return (steps ?? []).filter((s) => !s.ok).map((s) => s.name);
}

/** The server's 400 reasons, checked before a request (blank after trim), else null. */
export function replaceCertProblem(req: BMCReplaceCertRequest): string | null {
  if (!req.cert_pem?.trim()) return "A certificate PEM is required";
  if (!req.key_pem?.trim()) return "A private key PEM is required";
  return null;
}

export function bmcPath(profileID: string, op: string): string {
  return `/v1/bmc/${encodeURIComponent(profileID)}/${op}`;
}

export function useBMCCertOps(profileID: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      enroll: (opts?: BMCEnrollOptions) =>
        api.post<BMCEnrollResult>(bmcPath(profileID, "enroll"), { ...(opts ?? {}) }),
      restoreFactoryCert: () => api.post<BMCRestoreResult>(bmcPath(profileID, "cert/restore"), {}),
      replaceWebCertificate: (req: BMCReplaceCertRequest) =>
        api.put<{ status: string }>(bmcPath(profileID, "cert"), {
          cert_pem: req.cert_pem,
          key_pem: req.key_pem,
        }),
    };
  }, [client, profileID]);
}
