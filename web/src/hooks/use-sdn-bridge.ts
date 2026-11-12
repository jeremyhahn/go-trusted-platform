"use client";

/**
 * useSDNBridge loads one SDN bridge, its ports and the SDN policies for the
 * bridge detail page (#1745).
 */
import { useApi, useSDN } from 'trusted-platform-sdk';
import type { Bridge, Port, SDNPolicy } from 'trusted-platform-sdk';

export interface UseSDNBridgeResult {
  bridge: Bridge | null;
  ports: Port[];
  policies: SDNPolicy[];
  loading: boolean;
  refetchBridge: () => void;
  refetchPorts: () => void;
  refetchPolicies: () => void;
}

export function useSDNBridge(bridgeId: string): UseSDNBridgeResult {
  const sdn = useSDN();

  const bridgeQuery = useApi(
    () => (bridgeId ? sdn.getBridge(bridgeId) : Promise.resolve({ success: true, data: null })),
    [bridgeId]
  );
  const portsQuery = useApi(
    () => (bridgeId ? sdn.listPorts({ bridgeId }) : Promise.resolve({ success: true, data: null })),
    [bridgeId]
  );
  const policiesQuery = useApi(() => sdn.listPolicies(), []);

  return {
    bridge: bridgeQuery.data?.bridge ?? null,
    ports: portsQuery.data?.ports ?? [],
    policies: policiesQuery.data?.policies ?? [],
    loading: bridgeQuery.isLoading,
    refetchBridge: () => {
      void bridgeQuery.refetch();
    },
    refetchPorts: () => {
      void portsQuery.refetch();
    },
    refetchPolicies: () => {
      void policiesQuery.refetch();
    },
  };
}
