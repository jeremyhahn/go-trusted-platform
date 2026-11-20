"use client";

import { useCallback, useEffect, useRef, useState } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';
// Wire shapes of the SDK's VIP methods (sdk/javascript/src/types/gateway.ts).
// The SDK index does not re-export them, so they are restated here; the SDK
// methods accept them structurally.
export interface VIPBackend {
  address: string;
  port: number;
  weight?: number;
}

export interface VIPConfig {
  address: string;
  port: number;
  protocol: string;
  algorithm?: string;
  backends: VIPBackend[];
}

export interface VIPStatus {
  vip?: VIPConfig;
  ctZone?: number | string;
  groupId?: number | string;
  backends?: Array<{ backend?: VIPBackend; healthy?: boolean }>;
}

export interface SetVIPBackendsRequest {
  address: string;
  port: number;
  protocol: string;
  backends: VIPBackend[];
}

/** A backend row with its health, flattened for display. */
export interface GatewayVIPBackendRow {
  address: string;
  port: number;
  weight?: number;
  healthy?: boolean;
}

/** One VIP flattened for display. */
export interface GatewayVIPRow {
  address: string;
  port: number;
  protocol: string;
  algorithm?: string;
  ctZone?: number | string;
  groupId?: number | string;
  backends: GatewayVIPBackendRow[];
}

type SdkResult = { success: boolean; data?: unknown; error?: { message?: string } };

/**
 * The web service wraps every reply as {code, success, payload}; the daemon
 * returns the payload bare. Return the payload either way.
 */
export function payloadOf<T = unknown>(data: unknown): T | undefined {
  if (
    data !== null &&
    typeof data === 'object' &&
    'payload' in data &&
    'success' in data
  ) {
    return (data as { payload?: T }).payload;
  }
  return data as T | undefined;
}

/**
 * protojson sends uint64 as a decimal string. Parse it to a number when it
 * fits exactly, keep the exact string when it does not.
 */
export function toUint64(value: unknown): number | string | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (typeof value !== 'string' || !/^\d+$/.test(value)) return undefined;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : value;
}

/** Flatten a VIPStatus into a row. */
export function normalizeVIP(status: VIPStatus): GatewayVIPRow {
  const vip = status.vip;
  const configured = vip?.backends ?? [];
  const reported = status.backends ?? [];
  const backends: GatewayVIPBackendRow[] = reported.length
    ? reported.map((b) => ({
        address: b.backend?.address ?? '',
        port: Number(b.backend?.port ?? 0),
        weight: b.backend?.weight,
        healthy: b.healthy,
      }))
    : configured.map((b) => ({
        address: b.address,
        port: Number(b.port),
        weight: b.weight,
        healthy: undefined,
      }));
  return {
    address: vip?.address ?? '',
    port: Number(vip?.port ?? 0),
    protocol: vip?.protocol ?? '',
    algorithm: vip?.algorithm,
    ctZone: toUint64(status.ctZone),
    groupId: toUint64(status.groupId),
    backends,
  };
}

/**
 * Parse a backend list typed as `addr:port` entries separated by commas,
 * spaces or newlines. IPv6 goes in brackets (`[2001:db8::1]:443`); an
 * optional `@weight` follows the port. Throws on the first bad entry.
 */
export function parseBackends(text: string): VIPBackend[] {
  return text
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((entry) => {
      const m = /^(?:\[([^\]]+)\]|([^:@\s]+)):(\d{1,5})(?:@(\d+))?$/.exec(entry);
      const port = m ? Number(m[3]) : 0;
      if (!m || port < 1 || port > 65535) {
        throw new Error(`Invalid backend "${entry}": use address:port`);
      }
      const backend: VIPBackend = { address: m[1] ?? m[2], port };
      if (m[4] !== undefined) backend.weight = Number(m[4]);
      return backend;
    });
}

/** Throw a failed SDK result; return its unwrapped payload. */
function unwrap<T>(res: SdkResult, op: string): T | undefined {
  if (!res.success) {
    throw new Error(res.error?.message || `${op} failed`);
  }
  return payloadOf<T>(res.data);
}

function toError(e: unknown): Error {
  return e instanceof Error ? e : new Error(String(e));
}

export interface UseGatewayVIPsResult {
  vips: GatewayVIPRow[];
  isLoading: boolean;
  error: Error | undefined;
  lbStatus: Record<string, unknown> | undefined;
  lbError: Error | undefined;
  nat64Status: Record<string, unknown> | undefined;
  nat64Error: Error | undefined;
  refetch: () => Promise<void>;
  getVIP: (address: string, port: number, protocol: string) => Promise<GatewayVIPRow | undefined>;
  addVIP: (vip: VIPConfig) => Promise<void>;
  removeVIP: (address: string, port: number, protocol: string) => Promise<void>;
  setVIPBackends: (req: SetVIPBackendsRequest) => Promise<void>;
}

/**
 * Gateway load balancer VIPs with the LB and NAT64 status (#2052).
 *
 * The list and each status load on their own, so one unavailable service
 * leaves the others readable. Mutations throw on failure and reload on
 * success.
 */
export function useGatewayVIPs(): UseGatewayVIPsResult {
  const client = usePlatformClient();
  const gateway = client.gateway;

  const [vips, setVips] = useState<GatewayVIPRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | undefined>();
  const [lbStatus, setLbStatus] = useState<Record<string, unknown> | undefined>();
  const [lbError, setLbError] = useState<Error | undefined>();
  const [nat64Status, setNat64Status] = useState<Record<string, unknown> | undefined>();
  const [nat64Error, setNat64Error] = useState<Error | undefined>();
  const seq = useRef(0);

  const load = useCallback(async () => {
    const mine = ++seq.current;
    const [list, lb, nat] = await Promise.allSettled([
      gateway.listVIPs().then((r) => unwrap<{ vips?: VIPStatus[] }>(r, 'List VIPs')),
      gateway.getLBStatus().then((r) => unwrap<Record<string, unknown>>(r, 'LB status')),
      gateway.getNAT64Status().then((r) => unwrap<Record<string, unknown>>(r, 'NAT64 status')),
    ]);
    if (mine !== seq.current) return;
    if (list.status === 'fulfilled') {
      setVips((list.value?.vips ?? []).map(normalizeVIP));
      setError(undefined);
    } else {
      setVips([]);
      setError(toError(list.reason));
    }
    if (lb.status === 'fulfilled') {
      setLbStatus(lb.value ?? {});
      setLbError(undefined);
    } else {
      setLbStatus(undefined);
      setLbError(toError(lb.reason));
    }
    if (nat.status === 'fulfilled') {
      setNat64Status(nat.value ?? {});
      setNat64Error(undefined);
    } else {
      setNat64Status(undefined);
      setNat64Error(toError(nat.reason));
    }
    setIsLoading(false);
  }, [gateway]);

  useEffect(() => {
    // load() sets state only after its requests settle, never synchronously.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    void load();
  }, [load]);

  const getVIP = useCallback(
    async (address: string, port: number, protocol: string) => {
      const resp = unwrap<{ vip?: VIPStatus }>(await gateway.getVIP(address, port, protocol), 'Get VIP');
      return resp?.vip ? normalizeVIP(resp.vip) : undefined;
    },
    [gateway]
  );
  const addVIP = useCallback(
    async (vip: VIPConfig) => {
      unwrap(await gateway.addVIP(vip), 'Add VIP');
      await load();
    },
    [gateway, load]
  );
  const removeVIP = useCallback(
    async (address: string, port: number, protocol: string) => {
      unwrap(await gateway.removeVIP(address, port, protocol), 'Remove VIP');
      await load();
    },
    [gateway, load]
  );
  const setVIPBackends = useCallback(
    async (req: SetVIPBackendsRequest) => {
      unwrap(await gateway.setVIPBackends(req), 'Set VIP backends');
      await load();
    },
    [gateway, load]
  );

  return {
    vips,
    isLoading,
    error,
    lbStatus,
    lbError,
    nat64Status,
    nat64Error,
    refetch: load,
    getVIP,
    addVIP,
    removeVIP,
    setVIPBackends,
  };
}
