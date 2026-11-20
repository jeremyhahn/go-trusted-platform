'use client';

import * as React from 'react';
import type {
  ApiResponse,
  DNSRecord,
  DNSSECStatus,
  DNSService,
  RecordType,
  ResolveResponse,
  UpdateZoneRequest,
  UpdateZoneResponse,
} from 'trusted-platform-sdk';

/** The DNSService methods useDnsOps drives; the SDK's DNSService satisfies it. */
export type DnsOpsService = Pick<
  DNSService,
  | 'updateZone'
  | 'signZone'
  | 'getDNSSECStatus'
  | 'addRecord'
  | 'updateRecord'
  | 'deleteRecord'
  | 'listRecords'
  | 'resolve'
  | 'register'
>;

/** A record type in its short (A) or protobuf (RECORD_TYPE_A) form. */
type DnsRecordType = RecordType | `RECORD_TYPE_${RecordType}`;

/** Returns the data of a successful response, or throws the server's message. */
function unwrap<T>(res: ApiResponse<T>): T {
  if (!res.success) {
    throw new Error(res.error?.message ?? 'request failed');
  }
  const status = (res.data as { status?: { success?: boolean; message?: string } } | undefined)?.status;
  if (status && status.success === false) {
    throw new Error(status.message || 'request failed');
  }
  return res.data as T;
}

export interface UseDnsOpsResult {
  /** The last error of any operation, cleared when the next one starts. */
  error: string | null;
  /** True while an operation is in flight. */
  busy: boolean;
  updateZone: (req: UpdateZoneRequest) => Promise<UpdateZoneResponse | null>;
  signZone: (zone: string) => Promise<true | null>;
  getDNSSECStatus: (zone: string) => Promise<DNSSECStatus | null>;
  addRecord: (zone: string, record: DNSRecord) => Promise<true | null>;
  updateRecord: (zone: string, oldRecord: DNSRecord, newRecord: DNSRecord) => Promise<true | null>;
  deleteRecord: (zone: string, type: DnsRecordType, name: string) => Promise<true | null>;
  listRecords: (zone: string, type?: DnsRecordType) => Promise<DNSRecord[] | null>;
  resolve: (fqdn: string, type: DnsRecordType) => Promise<ResolveResponse | null>;
  register: (fqdn: string, ip: string) => Promise<true | null>;
}

/**
 * useDnsOps drives the DNS operations of row #2060 through the SDK's
 * DNSService: zone settings, DNSSEC, records, Resolve and Register. Each call
 * returns null on failure and leaves the server's message in `error`.
 */
export function useDnsOps(service: DnsOpsService): UseDnsOpsResult {
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

  return React.useMemo<UseDnsOpsResult>(
    () => ({
      error,
      busy,
      updateZone: (req) => run(async () => unwrap(await service.updateZone(req))),
      signZone: (zone) =>
        run(async () => {
          unwrap(await service.signZone(zone));
          return true as const;
        }),
      getDNSSECStatus: (zone) => run(async () => unwrap(await service.getDNSSECStatus(zone)).status),
      addRecord: (zone, record) =>
        run(async () => {
          unwrap(await service.addRecord({ zoneName: zone, record }));
          return true as const;
        }),
      updateRecord: (zone, oldRecord, newRecord) =>
        run(async () => {
          unwrap(await service.updateRecord({ zoneName: zone, oldRecord, newRecord }));
          return true as const;
        }),
      deleteRecord: (zone, type, name) =>
        run(async () => {
          unwrap(await service.deleteRecord({ zoneName: zone, type, name }));
          return true as const;
        }),
      listRecords: (zone, type) =>
        run(async () => {
          const res = unwrap(await service.listRecords(type ? { zoneName: zone, type } : { zoneName: zone }));
          return res?.records ?? [];
        }),
      resolve: (fqdn, type) => run(async () => unwrap(await service.resolve({ fqdn, type }))),
      register: (fqdn, ip) =>
        run(async () => {
          unwrap(await service.register({ fqdn, ip }));
          return true as const;
        }),
    }),
    [error, busy, run, service]
  );
}
