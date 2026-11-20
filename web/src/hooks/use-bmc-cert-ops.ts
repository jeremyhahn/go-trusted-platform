'use client';
import * as React from 'react';
import { usePlatformClient, type ApiResponse, type EnrollBMCRequest } from 'trusted-platform-sdk';

/**
 * Wire shapes of POST /api/v1/bmc/{profileID}/enroll and
 * POST /api/v1/bmc/{profileID}/cert/restore (pkg/webservice/v1/bmc/enroll.go
 * and cert_restore.go). The hook calls them through the SDK client's
 * BMCService.enrollBMC and restoreFactoryCert (#2040).
 */
export interface BMCEnrollOptions {
  /** Overrides the profile's replace_certificate enrolment flag. */
  replaceCertificate?: boolean;
  /** Overrides the profile's rotate_password enrolment flag. */
  rotatePassword?: boolean;
  /** Overrides the profile's dns_register enrolment flag. */
  dnsRegister?: boolean;
  /** Overrides the profile's dane_publish enrolment flag. */
  danePublish?: boolean;
}

export interface BMCEnrollStep {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface BMCFactoryCertMeta {
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
  factory_cert_meta?: BMCFactoryCertMeta;
  new_cert_pem?: string;
  ca_cert_pem?: string;
  steps: BMCEnrollStep[];
}

/** The restore answer: the restored certificate and the steps run. */
export interface BMCRestoreResult {
  device_id?: string;
  endpoint?: string;
  hostname?: string;
  new_cert_meta?: BMCFactoryCertMeta;
  new_cert_pem?: string;
  steps?: BMCEnrollStep[];
}

export type BMCCertOperation = 'enroll' | 'restore';

export interface BMCCertOpResult {
  operation: BMCCertOperation;
  result: BMCEnrollResult | BMCRestoreResult;
}

export interface UseBMCCertOpsResult {
  /** The last error of either operation, cleared when the next one starts. */
  error: string | null;
  /** True while an operation is in flight. */
  busy: boolean;
  /** The answer of the last operation that succeeded. */
  lastResult: BMCCertOpResult | null;
  enroll: (options: BMCEnrollOptions) => Promise<BMCEnrollResult | null>;
  restoreFactoryCert: () => Promise<BMCRestoreResult | null>;
}

/**
 * payloadOf turns an SDK answer into its payload, or an Error carrying the
 * server's message (a 403 for a missing scope, a 503, ...).
 */
export function payloadOf<T>(res: ApiResponse<unknown>): T {
  if (!res.success) {
    throw new Error(res.error?.message || 'BMC request failed');
  }
  return (res.data ?? {}) as T;
}

function enrollBody(options: BMCEnrollOptions): EnrollBMCRequest {
  // Only the options the operator set are sent; the SDK maps them to the
  // replace_certificate, rotate_password, dns_register and dane_publish fields.
  const body: EnrollBMCRequest = {};
  if (options.replaceCertificate !== undefined) body.replaceCertificate = options.replaceCertificate;
  if (options.rotatePassword !== undefined) body.rotatePassword = options.rotatePassword;
  if (options.dnsRegister !== undefined) body.dnsRegister = options.dnsRegister;
  if (options.danePublish !== undefined) body.danePublish = options.danePublish;
  return body;
}

/**
 * useBMCCertOps drives BMCService.EnrollBMC and RestoreFactoryCert for one
 * BMC profile.
 */
export function useBMCCertOps(profileID: string): UseBMCCertOpsResult {
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [lastResult, setLastResult] = React.useState<BMCCertOpResult | null>(null);
  const bmc = usePlatformClient().bmc;

  const run = React.useCallback(
    async <T extends BMCEnrollResult | BMCRestoreResult>(
      operation: BMCCertOperation,
      fn: () => Promise<T>
    ): Promise<T | null> => {
      setBusy(true);
      setError(null);
      try {
        const result = await fn();
        setLastResult({ operation, result });
        return result;
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    []
  );

  return React.useMemo<UseBMCCertOpsResult>(
    () => ({
      error,
      busy,
      lastResult,
      enroll: (options) =>
        run('enroll', async () => payloadOf<BMCEnrollResult>(await bmc.enrollBMC(profileID, enrollBody(options)))),
      restoreFactoryCert: () =>
        run('restore', async () => payloadOf<BMCRestoreResult>(await bmc.restoreFactoryCert(profileID))),
    }),
    [error, busy, lastResult, run, bmc, profileID]
  );
}
