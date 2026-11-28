"use client";

/**
 * useSDNIPAMPools reads and writes the gateway IPAM pools through the SDK
 * SDNService on `/api/v1/sdn/gateway/ipam/pools`
 * (pkg/webservice/v1/rest/gateway/ipam.go: POST creates, GET lists with an
 * optional ?zone=, PUT and DELETE on /{id} update and delete).
 */

import * as React from 'react';
import { useSDN, type SDNService } from 'trusted-platform-sdk';

type Data<F extends (...args: never[]) => Promise<{ data?: unknown }>> = NonNullable<Awaited<ReturnType<F>>['data']>;

/** SDNIPAMPoolList is the listIPAMPools response payload. */
export type SDNIPAMPoolList = Data<SDNService['listIPAMPools']>;
/** SDNIPAMPool is one pool as the server answers it. */
export type SDNIPAMPool = SDNIPAMPoolList['pools'][number];
/** SDNIPAMPoolRequest is the create and update request body. */
export type SDNIPAMPoolRequest = Parameters<SDNService['createIPAMPool']>[0];
/** SDNIPAMAllocation is one address allocation of a pool. */
export type SDNIPAMAllocation = Data<SDNService['listIPAMAllocations']>['allocations'][number];

export interface UseSDNIPAMPoolsResult {
  pools: SDNIPAMPool[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
  create: (request: SDNIPAMPoolRequest) => Promise<SDNIPAMPool | undefined>;
  update: (id: string, request: SDNIPAMPoolRequest) => Promise<SDNIPAMPool | undefined>;
  remove: (id: string) => Promise<void>;
  /** get reads one pool (GET /sdn/gateway/ipam/pools/{id}). */
  get: (id: string) => Promise<SDNIPAMPool>;
  /** listAllocations lists one pool's allocations (GET /sdn/gateway/ipam/allocations?pool_id=). */
  listAllocations: (poolId: string) => Promise<SDNIPAMAllocation[]>;
}

/** apiFailure turns an SDK refusal into the hook's Error, keeping the HTTP status. */
function apiFailure(error: { status?: number; message: string }): Error {
  return new Error(error.status !== undefined ? `HTTP ${error.status}: ${error.message}` : error.message);
}

/**
 * useSDNIPAMPools lists the pools of one zone (or every zone when zone is
 * empty) and creates, updates or deletes pools, listing again after each
 * change. A refused change rejects with the HTTP status.
 */
export function useSDNIPAMPools(zone?: string): UseSDNIPAMPoolsResult {
  const sdn = useSDN();
  const [pools, setPools] = React.useState<SDNIPAMPool[]>([]);
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  // Every read takes a sequence number and publishes only while it is still
  // the newest one, so a read for an old zone never replaces a newer one.
  const seq = React.useRef(0);

  const read = React.useCallback(async () => {
    const id = ++seq.current;
    try {
      const res = await sdn.listIPAMPools(zone ? { zone } : {});
      if (id !== seq.current) return;
      if (res.error) {
        setError(apiFailure(res.error).message);
        setPools([]);
      } else {
        setError(null);
        setPools(res.data?.pools ?? []);
      }
    } catch (err) {
      if (id !== seq.current) return;
      setError(err instanceof Error ? err.message : String(err));
      setPools([]);
    } finally {
      if (id === seq.current) setIsLoading(false);
    }
  }, [sdn, zone]);

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

  const create = React.useCallback(
    async (request: SDNIPAMPoolRequest) => {
      const res = await sdn.createIPAMPool(request);
      if (res.error) throw apiFailure(res.error);
      await refetch();
      return res.data;
    },
    [sdn, refetch]
  );

  const update = React.useCallback(
    async (id: string, request: SDNIPAMPoolRequest) => {
      const res = await sdn.updateIPAMPool(id, request);
      if (res.error) throw apiFailure(res.error);
      await refetch();
      return res.data;
    },
    [sdn, refetch]
  );

  const remove = React.useCallback(
    async (id: string) => {
      const res = await sdn.deleteIPAMPool(id);
      if (res.error) throw apiFailure(res.error);
      await refetch();
    },
    [sdn, refetch]
  );

  const get = React.useCallback(
    async (id: string) => {
      const res = await sdn.getIPAMPool(id);
      if (res.error) throw apiFailure(res.error);
      if (!res.data) throw new Error(`pool ${id} was not returned`);
      return res.data;
    },
    [sdn]
  );

  const listAllocations = React.useCallback(
    async (poolId: string) => {
      const res = await sdn.listIPAMAllocations({ poolId });
      if (res.error) throw apiFailure(res.error);
      return res.data?.allocations ?? [];
    },
    [sdn]
  );

  return { pools, isLoading, error, refetch, create, update, remove, get, listAllocations };
}
