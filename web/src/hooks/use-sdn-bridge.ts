"use client";

/**
 * useSDNBridge loads one SDN bridge, its ports and the SDN policies for the
 * bridge detail page (#1745).
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { useApi, useSDN } from 'trusted-platform-sdk';
import type { Bridge, Port, SDNPolicy } from 'trusted-platform-sdk';

export interface UseSDNBridgeResult {
  bridge: Bridge | null;
  ports: Port[];
  policies: SDNPolicy[];
  loading: boolean;
  bridgeError: string | null;
  portsError: string | null;
  policiesError: string | null;
  /**
   * True only once the policy list read has succeeded. While it is pending or
   * after it is refused, `policies` is an empty stand-in, not "no policies".
   */
  policiesLoaded: boolean;
  refetchBridge: () => void;
  refetchPorts: () => void;
  refetchPolicies: () => void;
}

/** One load's outcome, tagged with the bridge it was made for. */
interface Tagged<T> {
  bridgeId: string;
  value: T;
  error: string | null;
}

type Reply = { success?: boolean; error?: { message?: string } | null };

function failure(res: Reply): string | null {
  if (res.success === false || (res.error !== undefined && res.error !== null)) {
    return res.error?.message || 'Request failed';
  }
  return null;
}

function thrown(err: unknown): string {
  return (err instanceof Error ? err.message : String(err)) || 'Request failed';
}

export function useSDNBridge(bridgeId: string): UseSDNBridgeResult {
  const sdn = useSDN();

  // The bridge and its ports load in hook-local state: each load is tagged
  // with the bridge it was made for and a sequence number, so a reply for a
  // superseded bridge, or older than the newest request, is dropped, and a
  // result for another bridge is never shown (#2125 Codex).
  const [bridgeState, setBridgeState] = useState<Tagged<Bridge | null> | undefined>(undefined);
  const [portsState, setPortsState] = useState<Tagged<Port[]> | undefined>(undefined);
  const bridgeSeq = useRef(0);
  const portsSeq = useRef(0);
  const bridgeRef = useRef(bridgeId);
  // Declared before the load effects so the current bridge is recorded
  // before any load for it starts.
  useEffect(() => {
    bridgeRef.current = bridgeId;
  }, [bridgeId]);
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const loadBridge = useCallback(async () => {
    const seq = ++bridgeSeq.current;
    const forId = bridgeId;
    if (!forId) {
      return;
    }
    const settle = (next: Tagged<Bridge | null>) => {
      if (!mountedRef.current || seq !== bridgeSeq.current || forId !== bridgeRef.current) {
        return;
      }
      setBridgeState(next);
    };
    try {
      const res = await sdn.getBridge(forId);
      const error = failure(res);
      settle({ bridgeId: forId, value: error ? null : (res.data?.bridge ?? null), error });
    } catch (err) {
      settle({ bridgeId: forId, value: null, error: thrown(err) });
    }
  }, [sdn, bridgeId]);

  const loadPorts = useCallback(async () => {
    const seq = ++portsSeq.current;
    const forId = bridgeId;
    if (!forId) {
      return;
    }
    const settle = (next: Tagged<Port[]>) => {
      if (!mountedRef.current || seq !== portsSeq.current || forId !== bridgeRef.current) {
        return;
      }
      setPortsState(next);
    };
    try {
      const res = await sdn.listPorts({ bridgeId: forId });
      const error = failure(res);
      settle({ bridgeId: forId, value: error ? [] : (res.data?.ports ?? []), error });
    } catch (err) {
      settle({ bridgeId: forId, value: [], error: thrown(err) });
    }
  }, [sdn, bridgeId]);

  useEffect(() => {
    void loadBridge();
  }, [loadBridge]);
  useEffect(() => {
    void loadPorts();
  }, [loadPorts]);

  const policiesQuery = useApi(() => sdn.listPolicies(), []);

  const bridgeCur = bridgeId && bridgeState?.bridgeId === bridgeId ? bridgeState : undefined;
  const portsCur = bridgeId && portsState?.bridgeId === bridgeId ? portsState : undefined;

  return {
    bridge: bridgeCur?.value ?? null,
    ports: portsCur?.value ?? [],
    policies: policiesQuery.data?.policies ?? [],
    loading: bridgeId !== '' && bridgeCur === undefined,
    bridgeError: bridgeCur?.error ?? null,
    portsError: portsCur?.error ?? null,
    policiesError: policiesQuery.isError ? policiesQuery.error?.message || 'Request failed' : null,
    policiesLoaded: !policiesQuery.isLoading && !policiesQuery.isError && !!policiesQuery.data,
    refetchBridge: () => {
      void loadBridge();
    },
    refetchPorts: () => {
      void loadPorts();
    },
    refetchPolicies: () => {
      void policiesQuery.refetch();
    },
  };
}
