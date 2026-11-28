'use client';

import * as React from 'react';
import { useApi, usePlatformClient } from 'trusted-platform-sdk';
import type {
  SetSwitchPortVLANResponse,
  SwitchPortActionResponse,
  SwitchPortStatus,
} from 'trusted-platform-sdk';

/** The client resolves failed requests as { success: false }; turn them into a rejection. */
function failure(message: string | undefined): Error {
  return new Error(message || 'Request failed');
}

/**
 * The ports of one managed switch (#2066) through the SDK SwitchService:
 * the port list, a single port's status, and the port writes. A write the
 * server refuses rejects with its message; a successful one re-reads the ports.
 */
export function useSwitches(switchName: string) {
  const switches = usePlatformClient().switches;

  const { data, isLoading, error, refetch } = useApi<SwitchPortStatus[]>(
    () => switches.listPorts(switchName),
    [switches, switchName],
    { enabled: switchName !== '' }
  );

  const getPortStatus = React.useCallback(
    async (port: string): Promise<SwitchPortStatus | undefined> => {
      const res = await switches.getPortStatus(switchName, port);
      if (!res.success) throw failure(res.error?.message);
      return res.data;
    },
    [switches, switchName]
  );

  const enablePort = React.useCallback(
    async (port: string): Promise<SwitchPortActionResponse | undefined> => {
      const res = await switches.enablePort(switchName, port);
      if (!res.success) throw failure(res.error?.message);
      await refetch();
      return res.data;
    },
    [switches, switchName, refetch]
  );

  const disablePort = React.useCallback(
    async (port: string): Promise<SwitchPortActionResponse | undefined> => {
      const res = await switches.disablePort(switchName, port);
      if (!res.success) throw failure(res.error?.message);
      await refetch();
      return res.data;
    },
    [switches, switchName, refetch]
  );

  const setPortVLAN = React.useCallback(
    async (port: string, vlanId: number): Promise<SetSwitchPortVLANResponse | undefined> => {
      const res = await switches.setPortVLAN(switchName, port, vlanId);
      if (!res.success) throw failure(res.error?.message);
      await refetch();
      return res.data;
    },
    [switches, switchName, refetch]
  );

  return {
    ports: data ?? [],
    isLoading,
    error,
    refetch,
    getPortStatus,
    enablePort,
    disablePort,
    setPortVLAN,
  };
}
