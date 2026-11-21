"use client";

/**
 * useGatewayIPAM reads and writes gateway IP allocations through the SDK
 * GatewayService on the webservice surface `/api/v1/gateway/ipam/allocations`
 * (pkg/webservice/v1/rest/gateway/router.go: GET lists, POST allocates,
 * DELETE ?ip= releases), not the daemon `/api/v1/sdn/gateway` path.
 */

import * as React from 'react';
import { useGateway, type GatewayService } from 'trusted-platform-sdk';

type Data<F extends (...args: never[]) => Promise<{ data?: unknown }>> = NonNullable<Awaited<ReturnType<F>>['data']>;

/** GatewayAllocationList is the ListAllocations response payload. */
export type GatewayAllocationList = Data<GatewayService['listAllocations']>;
/** GatewayIPAllocation is one leased address. */
export type GatewayIPAllocation = GatewayAllocationList['allocations'][number];
/** GatewayAllocateRequest is the AllocateIP request body. */
export type GatewayAllocateRequest = Parameters<GatewayService['allocateIP']>[0];

export interface UseGatewayIPAMResult {
  allocations: GatewayIPAllocation[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  allocate: (request: GatewayAllocateRequest) => Promise<GatewayIPAllocation | undefined>;
  release: (ip: string) => Promise<void>;
}

/** apiFailure turns an SDK refusal into the hook's Error, keeping the HTTP status. */
function apiFailure(error: { status?: number; message: string }): Error {
  return new Error(error.status !== undefined ? `HTTP ${error.status}: ${error.message}` : error.message);
}

/**
 * useGatewayIPAM lists the allocations of one pool (or every pool when
 * poolId is empty) and allocates or releases addresses, listing again after
 * each change. A refused allocate or release rejects with the HTTP status.
 */
export function useGatewayIPAM(poolId?: string): UseGatewayIPAMResult {
  const gateway = useGateway();
  const [allocations, setAllocations] = React.useState<GatewayIPAllocation[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // #2184 Codex: every read (effect, refetch, mutation refetch) takes a
  // sequence number and publishes only while it is still the newest one. A
  // pool or client change bumps the sequence in the effect cleanup, so reads
  // started for the old pool are dropped, and an older read resolving after a
  // newer one never replaces it.
  const seq = React.useRef(0);

  const read = React.useCallback(async () => {
    const id = ++seq.current;
    try {
      const res = await gateway.listAllocations(poolId ? { poolId } : undefined);
      if (id !== seq.current) return;
      if (res.error) {
        setError(apiFailure(res.error).message);
        setAllocations([]);
      } else {
        setError(null);
        setAllocations(res.data?.allocations ?? []);
      }
    } finally {
      if (id === seq.current) setIsLoading(false);
    }
  }, [gateway, poolId]);

  // A mutation awaits refetch after its request; latestRead makes that
  // refetch list the pool current when it runs, not the one it captured.
  const latestRead = React.useRef(read);
  React.useLayoutEffect(() => {
    latestRead.current = read;
  }, [read]);
  const refetch = React.useCallback(() => latestRead.current(), []);

  React.useEffect(() => {
    void read();
    return () => {
      seq.current++;
    };
  }, [read]);

  const allocate = React.useCallback(
    async (request: GatewayAllocateRequest) => {
      const res = await gateway.allocateIP(request);
      if (res.error) throw apiFailure(res.error);
      if (res.data?.status && res.data.status.success === false) {
        throw new Error(res.data.status.message || 'allocation refused');
      }
      await refetch();
      return res.data?.allocation;
    },
    [gateway, refetch]
  );

  const release = React.useCallback(
    async (ip: string) => {
      const res = await gateway.releaseIP({ ip });
      if (res.error) throw apiFailure(res.error);
      if (res.data?.status && res.data.status.success === false) {
        throw new Error(res.data.status.message || 'release refused');
      }
      await refetch();
    },
    [gateway, refetch]
  );

  return { allocations, isLoading, error, refetch, allocate, release };
}
