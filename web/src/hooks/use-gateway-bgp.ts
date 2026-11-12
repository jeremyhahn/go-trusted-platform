'use client';
import * as React from 'react';

/** One BGP peer as the gateway reports it. */
export interface GatewayBGPPeer {
  address: string;
  asn: number;
  state: string;
  prefixesReceived: number;
}

/** One prefix the gateway announces. */
export interface GatewayAnnouncedPrefix {
  prefix: string;
  nextHop: string;
}

/** One IPAM allocation. */
export interface GatewayIPAllocation {
  ip: string;
  poolId: string;
  hostname: string;
  status: string;
}

export interface UseGatewayBgpResult {
  peers: GatewayBGPPeer[];
  prefixes: GatewayAnnouncedPrefix[];
  allocations: GatewayIPAllocation[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  announcePrefix: (prefix: string, nextHop: string) => Promise<void>;
  withdrawPrefix: (prefix: string) => Promise<void>;
  allocateIP: (poolId: string, hostname: string) => Promise<GatewayIPAllocation | null>;
  releaseIP: (ip: string) => Promise<void>;
}

const BASE = '/api/v1/gateway';

type Raw = Record<string, unknown>;

// The REST layer serialises protobuf messages; depending on the marshaller a
// field arrives in lowerCamelCase or in its proto (snake_case) name. Read both.
function field(obj: Raw, camel: string, snake: string): unknown {
  return obj[camel] ?? obj[snake];
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : v === undefined || v === null ? '' : String(v);
}

function num(v: unknown): number {
  const n = typeof v === 'number' ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}

function list(body: unknown, key: string): Raw[] {
  if (body && typeof body === 'object') {
    const v = (body as Raw)[key];
    if (Array.isArray(v)) return v.filter((x): x is Raw => !!x && typeof x === 'object');
  }
  return [];
}

export function toPeer(r: Raw): GatewayBGPPeer {
  return {
    address: str(r.address),
    asn: num(r.asn),
    state: str(r.state),
    prefixesReceived: num(field(r, 'prefixesReceived', 'prefixes_received')),
  };
}

export function toPrefix(r: Raw): GatewayAnnouncedPrefix {
  return { prefix: str(r.prefix), nextHop: str(field(r, 'nextHop', 'next_hop')) };
}

export function toAllocation(r: Raw): GatewayIPAllocation {
  return {
    ip: str(r.ip),
    poolId: str(field(r, 'poolId', 'pool_id')),
    hostname: str(r.hostname),
    status: str(r.status),
  };
}

async function call(path: string, init?: RequestInit): Promise<unknown> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'include',
    ...init,
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
  });
  const text = await res.text();
  let body: unknown = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!res.ok) {
    const msg =
      body && typeof body === 'object'
        ? str((body as Raw).message ?? (body as Raw).error)
        : '';
    throw new Error(msg || `request failed with status ${res.status}`);
  }
  return body;
}

/**
 * The gateway's BGP peers, announced prefixes and IPAM allocations, with the
 * four mutations the web service routes: announce and withdraw a prefix,
 * allocate and release an IP. The web service takes the withdraw prefix and
 * the release IP as query parameters.
 */
export function useGatewayBgp(): UseGatewayBgpResult {
  const [peers, setPeers] = React.useState<GatewayBGPPeer[]>([]);
  const [prefixes, setPrefixes] = React.useState<GatewayAnnouncedPrefix[]>([]);
  const [allocations, setAllocations] = React.useState<GatewayIPAllocation[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  const refetch = React.useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [p, x, a] = await Promise.all([
        call('/bgp/peers'),
        call('/bgp/prefixes'),
        call('/ipam/allocations'),
      ]);
      setPeers(list(p, 'peers').map(toPeer));
      setPrefixes(list(x, 'prefixes').map(toPrefix));
      setAllocations(list(a, 'allocations').map(toAllocation));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void refetch();
  }, [refetch]);

  const announcePrefix = React.useCallback(
    async (prefix: string, nextHop: string) => {
      await call('/bgp/prefixes', {
        method: 'POST',
        body: JSON.stringify({ prefix, next_hop: nextHop }),
      });
      await refetch();
    },
    [refetch]
  );

  const withdrawPrefix = React.useCallback(
    async (prefix: string) => {
      await call(`/bgp/prefixes?prefix=${encodeURIComponent(prefix)}`, { method: 'DELETE' });
      await refetch();
    },
    [refetch]
  );

  const allocateIP = React.useCallback(
    async (poolId: string, hostname: string) => {
      const body = await call('/ipam/allocations', {
        method: 'POST',
        body: JSON.stringify({ pool_id: poolId, hostname }),
      });
      await refetch();
      const alloc = body && typeof body === 'object' ? (body as Raw).allocation : undefined;
      return alloc && typeof alloc === 'object' ? toAllocation(alloc as Raw) : null;
    },
    [refetch]
  );

  const releaseIP = React.useCallback(
    async (ip: string) => {
      await call(`/ipam/allocations?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' });
      await refetch();
    },
    [refetch]
  );

  return {
    peers,
    prefixes,
    allocations,
    isLoading,
    error,
    refetch,
    announcePrefix,
    withdrawPrefix,
    allocateIP,
    releaseIP,
  };
}
