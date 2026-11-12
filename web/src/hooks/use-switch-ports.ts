"use client";

import { useCallback } from 'react';
import { useApi, usePlatformClient } from 'trusted-platform-sdk';
import type {
  SwitchPortActionResponse,
  SwitchPortStatus,
  SwitchSetPortVLANResponse,
} from 'trusted-platform-sdk';

export interface UseSwitchPortsResult {
  ports: SwitchPortStatus[];
  isLoading: boolean;
  error: Error | undefined;
  refetch: () => void;
  getPortStatus: (port: string) => Promise<SwitchPortStatus | undefined>;
  enablePort: (port: string) => Promise<SwitchPortActionResponse | undefined>;
  disablePort: (port: string) => Promise<SwitchPortActionResponse | undefined>;
  setPortVLAN: (port: string, vlanId: number) => Promise<SwitchSetPortVLANResponse | undefined>;
}

/**
 * Ports of one switch and the operations on them (#1724).
 *
 * Every action resolves to the response payload, or throws the transport
 * error so the caller can show it.
 */
export function useSwitchPorts(switchName: string): UseSwitchPortsResult {
  const client = usePlatformClient();
  const service = client.switches;

  const { data, isLoading, error, refetch } = useApi(
    () => service.listPorts(switchName),
    [service, switchName]
  );

  const getPortStatus = useCallback(
    async (port: string) => (await service.getPortStatus(switchName, port)).data,
    [service, switchName]
  );
  const enablePort = useCallback(
    async (port: string) => (await service.enablePort(switchName, port)).data,
    [service, switchName]
  );
  const disablePort = useCallback(
    async (port: string) => (await service.disablePort(switchName, port)).data,
    [service, switchName]
  );
  const setPortVLAN = useCallback(
    async (port: string, vlanId: number) =>
      (await service.setPortVLAN(switchName, port, vlanId)).data,
    [service, switchName]
  );

  return {
    ports: Array.isArray(data) ? data : [],
    isLoading,
    error: error ?? undefined,
    refetch: () => void refetch(),
    getPortStatus,
    enablePort,
    disablePort,
    setPortVLAN,
  };
}
