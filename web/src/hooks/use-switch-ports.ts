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
/**
 * The PlatformProvider leaves throwOnError off, so a failed request resolves
 * to { success: false, error }. Throw it, so callers never read a failure as
 * success.
 */
function unwrap<T>(
  res: { success: boolean; data?: T; error?: { message?: string } },
  op: string
): T | undefined {
  if (!res.success) {
    throw new Error(res.error?.message || `${op} failed`);
  }
  return res.data;
}

export function useSwitchPorts(switchName: string): UseSwitchPortsResult {
  const client = usePlatformClient();
  const service = client.switches;

  const { data, isLoading, error, refetch } = useApi(
    () => service.listPorts(switchName),
    [service, switchName]
  );

  const getPortStatus = useCallback(
    async (port: string) => unwrap(await service.getPortStatus(switchName, port), 'Get port status'),
    [service, switchName]
  );
  const enablePort = useCallback(
    async (port: string) => unwrap(await service.enablePort(switchName, port), 'Enable port'),
    [service, switchName]
  );
  const disablePort = useCallback(
    async (port: string) => unwrap(await service.disablePort(switchName, port), 'Disable port'),
    [service, switchName]
  );
  const setPortVLAN = useCallback(
    async (port: string, vlanId: number) =>
      unwrap(await service.setPortVLAN(switchName, port, vlanId), 'Set port VLAN'),
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
