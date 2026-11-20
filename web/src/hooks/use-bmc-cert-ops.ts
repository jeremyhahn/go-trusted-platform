'use client';
import * as React from 'react';

/**
 * Wire shapes of POST /api/v1/bmc/{profileID}/enroll and
 * POST /api/v1/bmc/{profileID}/cert/restore (pkg/webservice/v1/bmc/enroll.go
 * and cert_restore.go). They mirror the SDK's BMCService.enrollBMC and
 * restoreFactoryCert; the calls go straight to the REST routes, as useBMC and
 * useBMCUsers do, because the web app consumes the built SDK package and the
 * two methods reach it only with the next SDK build.
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

async function call<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
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
    const env = parsed as { error?: { message?: string } | string; message?: string } | undefined;
    const msg =
      (typeof env?.error === 'object' ? env.error?.message : env?.error) ?? env?.message ?? `HTTP ${res.status}`;
    throw new Error(msg);
  }
  const env = parsed as { payload?: T } | undefined;
  return (env?.payload ?? parsed ?? {}) as T;
}

function enrollBody(options: BMCEnrollOptions): Record<string, boolean> {
  const body: Record<string, boolean> = {};
  if (options.replaceCertificate !== undefined) body.replace_certificate = options.replaceCertificate;
  if (options.rotatePassword !== undefined) body.rotate_password = options.rotatePassword;
  if (options.dnsRegister !== undefined) body.dns_register = options.dnsRegister;
  if (options.danePublish !== undefined) body.dane_publish = options.danePublish;
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
  const base = `/api/v1/bmc/${encodeURIComponent(profileID)}`;

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
      enroll: (options) => run('enroll', () => call<BMCEnrollResult>(`${base}/enroll`, enrollBody(options))),
      restoreFactoryCert: () => run('restore', () => call<BMCRestoreResult>(`${base}/cert/restore`, {})),
    }),
    [error, busy, lastResult, run, base]
  );
}
