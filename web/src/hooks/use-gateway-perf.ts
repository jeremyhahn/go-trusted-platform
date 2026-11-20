"use client";

import { useCallback, useEffect, useRef, useState } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';
import { payloadOf, toUint64 } from './use-gateway-vips';

/** One perf card's state. */
export interface PerfCard {
  data: Record<string, unknown> | undefined;
  error: Error | undefined;
  loading: boolean;
}

/**
 * The scalar fields of a perf payload as [name, value] pairs, uint64 strings
 * parsed. Nested objects and lists are left to the raw view.
 */
export function counterEntries(data: unknown): Array<[string, number | string | boolean]> {
  const payload = payloadOf<Record<string, unknown>>(data);
  if (!payload || typeof payload !== 'object') return [];
  const out: Array<[string, number | string | boolean]> = [];
  for (const [key, value] of Object.entries(payload)) {
    if (typeof value === 'boolean' || typeof value === 'number') {
      out.push([key, value]);
    } else if (typeof value === 'string') {
      out.push([key, toUint64(value) ?? value]);
    }
  }
  return out;
}

type SdkResult = { success: boolean; data?: unknown; error?: { message?: string } };

function settle(res: SdkResult, op: string): Record<string, unknown> {
  if (!res.success) {
    throw new Error(res.error?.message || `${op} failed`);
  }
  return payloadOf<Record<string, unknown>>(res.data) ?? {};
}

const idle: PerfCard = { data: undefined, error: undefined, loading: true };

export interface UseGatewayPerfResult {
  flows: PerfCard;
  datapath: PerfCard;
  conntrack: PerfCard;
  runFlows: () => Promise<void>;
  loadDatapath: (bridge?: string) => Promise<void>;
  loadConntrack: (zone?: number) => Promise<void>;
}

function useCard(
  fetcher: (...args: never[]) => Promise<SdkResult>,
  op: string
): [PerfCard, (...args: unknown[]) => Promise<void>] {
  const [card, setCard] = useState<PerfCard>(idle);
  const seq = useRef(0);
  const run = useCallback(
    async (...args: unknown[]) => {
      const mine = ++seq.current;
      setCard((c) => ({ ...c, loading: true }));
      try {
        const data = settle(await (fetcher as (...a: unknown[]) => Promise<SdkResult>)(...args), op);
        if (mine === seq.current) setCard({ data, error: undefined, loading: false });
      } catch (e) {
        if (mine === seq.current) {
          setCard({ data: undefined, error: e instanceof Error ? e : new Error(String(e)), loading: false });
        }
      }
    },
    [fetcher, op]
  );
  return [card, run];
}

/**
 * Gateway performance reports (#2052): the flows run, datapath counters
 * (optionally one bridge) and conntrack counters (optionally one zone).
 * Each card loads and fails on its own.
 */
export function useGatewayPerf(): UseGatewayPerfResult {
  const client = usePlatformClient();
  const gateway = client.gateway;

  const flowsFetch = useCallback(() => gateway.getPerfFlows(), [gateway]);
  const datapathFetch = useCallback((bridge?: string) => gateway.getPerfDatapath(bridge), [gateway]);
  const conntrackFetch = useCallback((zone?: number) => gateway.getPerfConntrack(zone), [gateway]);

  const [flows, runFlowsRaw] = useCard(flowsFetch, 'Perf flows');
  const [datapath, loadDatapathRaw] = useCard(datapathFetch, 'Perf datapath');
  const [conntrack, loadConntrackRaw] = useCard(conntrackFetch, 'Perf conntrack');

  const runFlows = useCallback(() => runFlowsRaw(), [runFlowsRaw]);
  const loadDatapath = useCallback((bridge?: string) => loadDatapathRaw(bridge), [loadDatapathRaw]);
  const loadConntrack = useCallback((zone?: number) => loadConntrackRaw(zone), [loadConntrackRaw]);

  useEffect(() => {
    void runFlows();
    void loadDatapath();
    void loadConntrack();
  }, [runFlows, loadDatapath, loadConntrack]);

  return { flows, datapath, conntrack, runFlows, loadDatapath, loadConntrack };
}
