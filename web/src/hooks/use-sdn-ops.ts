'use client';

/**
 * SDN operations the bridge and flow pages run on demand (#2064):
 * FlushFlows, GetFlowStats and DeletePolicy, through the SDK's SDN service.
 */
import { useCallback, useState } from 'react';
import { useSDN } from 'trusted-platform-sdk';
import type { FlowStats, FlowTable } from 'trusted-platform-sdk';

export type SDNOp = 'flushFlows' | 'getFlowStats' | 'deletePolicy';

export interface UseSDNOpsResult {
  /** The operation in flight, or null. */
  pending: SDNOp | null;
  /** The last operation's error, or null after a success. */
  error: string | null;
  /** Flushes the bridge's flows (one table when given); the deleted count, or null on failure. */
  flushFlows: (table?: FlowTable) => Promise<number | null>;
  /** One flow's statistics, or null on failure. */
  getFlowStats: (flowId: string) => Promise<FlowStats | null>;
  /** Deletes a policy; true when the server deleted it. */
  deletePolicy: (policyId: string) => Promise<boolean>;
}

interface Answer<T> {
  success: boolean;
  data?: T | null;
  error?: { message?: string } | null;
}

function failure(err: unknown): string {
  return err instanceof Error && err.message ? err.message : 'Request failed';
}

export function useSDNOps(bridgeId: string): UseSDNOpsResult {
  const sdn = useSDN();
  const [pending, setPending] = useState<SDNOp | null>(null);
  const [error, setError] = useState<string | null>(null);

  const run = useCallback(
    async <T,>(op: SDNOp, call: () => Promise<Answer<T>>): Promise<T | null> => {
      setPending(op);
      try {
        const res = await call();
        if (!res.success) {
          setError(res.error?.message || 'Request failed');
          return null;
        }
        setError(null);
        return (res.data ?? null) as T | null;
      } catch (err) {
        setError(failure(err));
        return null;
      } finally {
        setPending(null);
      }
    },
    []
  );

  const flushFlows = useCallback(
    async (table?: FlowTable): Promise<number | null> => {
      if (!bridgeId) {
        setError('Select a bridge first');
        return null;
      }
      const data = await run('flushFlows', () => sdn.flushFlows({ bridgeId, table }));
      return data ? Number(data.deletedCount ?? 0) : null;
    },
    [bridgeId, run, sdn]
  );

  const getFlowStats = useCallback(
    async (flowId: string): Promise<FlowStats | null> => {
      if (!bridgeId) {
        setError('Select a bridge first');
        return null;
      }
      const data = await run('getFlowStats', () => sdn.getFlowStats(bridgeId, flowId));
      return data?.stats ?? null;
    },
    [bridgeId, run, sdn]
  );

  const deletePolicy = useCallback(
    async (policyId: string): Promise<boolean> => {
      let ok = false;
      await run('deletePolicy', async () => {
        const res = await sdn.deletePolicy(policyId);
        ok = res.success;
        return res;
      });
      return ok;
    },
    [run, sdn]
  );

  return { pending, error, flushFlows, getFlowStats, deletePolicy };
}
