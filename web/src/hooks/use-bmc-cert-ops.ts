"use client";

/**
 * BMC certificate hook: EnrollBMC and RestoreFactoryCert on
 * `/api/v1/bmc/{profileID}/enroll` and `/cert/restore`
 * (pkg/webservice/v1/bmc enroll.go, cert_restore.go). The server's
 * `PUT /cert` replace is not offered: it rotates no SPKI pin and no TLSA
 * record (#2199).
 *
 * It calls the SDK BMCCertService (`client.bmcCert`), mapping the hook's
 * snake_case options to the SDK's camelCase ones; the SDK drops options left
 * out, so the wire body is the subset given. Results are snake_case and
 * `device_id` is a decimal string. Enroll always sends a JSON object because
 * the server refuses an empty body; restore sends none.
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

/** The names of the steps that did not succeed, in order; [] for undefined. */
export function failedCeremonySteps(steps?: BMCCeremonyStep[]): string[] {
  return (steps ?? []).filter((s) => !s.ok).map((s) => s.name);
}

export function bmcPath(profileID: string, op: string): string {
  return `/v1/bmc/${encodeURIComponent(profileID)}/${op}`;
}

export function useBMCCertOps(profileID: string) {
  const client = usePlatformClient();
  return useMemo(
    () => ({
      enroll: (opts?: BMCEnrollOptions) =>
        client.bmcCert.enrollBMC(profileID, {
          replaceCertificate: opts?.replace_certificate,
          rotatePassword: opts?.rotate_password,
          dnsRegister: opts?.dns_register,
          danePublish: opts?.dane_publish,
        }),
      restoreFactoryCert: () => client.bmcCert.restoreFactoryCert(profileID),
    }),
    [client, profileID],
  );
}
