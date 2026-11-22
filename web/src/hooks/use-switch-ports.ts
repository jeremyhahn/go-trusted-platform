"use client";

import { useCallback, useEffect, useRef, useState } from 'react';
import { isServiceNotConfigured, SERVICE_NOT_CONFIGURED, usePlatformClient } from 'trusted-platform-sdk';
import type {
  SwitchPortActionResponse,
  SwitchPortStatus,
  SwitchSetPortVLANResponse,
} from 'trusted-platform-sdk';

export interface UseSwitchPortsResult {
  ports: SwitchPortStatus[];
  isLoading: boolean;
  error: Error | undefined;
  /**
   * The server answered the structured 503: no switch service is wired on
   * this node. The capability the page gates every port control on.
   */
  unavailable: boolean;
  /** The server's reason when unavailable. */
  unavailableReason: string | undefined;
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

/**
 * With throwOnError off, useApi holds the response's { code, message,
 * details } without the HTTP status, so read the structured 503's reason
 * from details as well as through the SDK's thrown-error check.
 */
function switchNotConfigured(error: unknown): boolean {
  if (isServiceNotConfigured(error)) return true;
  const details = (error as { details?: { reason?: unknown } } | null | undefined)?.details;
  return details?.reason === SERVICE_NOT_CONFIGURED;
}

export function useSwitchPorts(switchName: string): UseSwitchPortsResult {
  const client = usePlatformClient();
  const service = client.switches;

  // Each listing is tagged with the switch it was made for and a sequence
  // number: a response for a superseded switch, or older than the newest
  // request, is dropped, and rows listed for another switch are never shown
  // (#2023 Codex).
  const [listing, setListing] = useState<PortListing | undefined>(undefined);
  const seqRef = useRef(0);
  const switchRef = useRef(switchName);
  switchRef.current = switchName;
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const load = useCallback(async () => {
    const seq = ++seqRef.current;
    const forSwitch = switchName;
    const settle = (next: PortListing) => {
      if (!mountedRef.current || seq !== seqRef.current || forSwitch !== switchRef.current) {
        return;
      }
      setListing(next);
    };
    try {
      const res = await service.listPorts(forSwitch);
      if (res.error !== undefined || res.success === false) {
        const resError = res.error as { message?: string; details?: unknown } | undefined;
        // Keep the server's details: the structured 503's reason marks the
        // switch service as not configured on this node.
        const listError = Object.assign(new Error(resError?.message || 'List ports failed'), {
          details: resError?.details,
        });
        settle({ switchName: forSwitch, ports: undefined, error: listError });
        return;
      }
      settle({ switchName: forSwitch, ports: Array.isArray(res.data) ? res.data : [], error: undefined });
    } catch (err) {
      settle({
        switchName: forSwitch,
        ports: undefined,
        error: err instanceof Error ? err : new Error(String(err)),
      });
    }
  }, [service, switchName]);

  useEffect(() => {
    void load();
  }, [load]);

  const current = listing?.switchName === switchName ? listing : undefined;
  const listingRef = useRef(listing);
  listingRef.current = listing;

  const requireListed = useCallback(
    (op: string) => {
      const l = listingRef.current;
      if (l?.switchName !== switchRef.current || l.ports === undefined) {
        throw new Error(`${op} refused: ports of ${switchRef.current} are not listed yet`);
      }
    },
    []
  );

  const getPortStatus = useCallback(
    async (port: string) => unwrap(await service.getPortStatus(switchName, port), 'Get port status'),
    [service, switchName]
  );
  const enablePort = useCallback(
    async (port: string) => {
      requireListed('Enable port');
      return unwrap(await service.enablePort(switchName, port), 'Enable port');
    },
    [service, switchName, requireListed]
  );
  const disablePort = useCallback(
    async (port: string) => {
      requireListed('Disable port');
      return unwrap(await service.disablePort(switchName, port), 'Disable port');
    },
    [service, switchName, requireListed]
  );
  const setPortVLAN = useCallback(
    async (port: string, vlanId: number) => {
      requireListed('Set port VLAN');
      return unwrap(await service.setPortVLAN(switchName, port, vlanId), 'Set port VLAN');
    },
    [service, switchName, requireListed]
  );

  const unavailable = switchNotConfigured(current?.error);

  return {
    ports: !unavailable ? (current?.ports ?? []) : [],
    isLoading: current === undefined,
    error: current?.error,
    unavailable,
    unavailableReason: unavailable
      ? current?.error?.message || 'Switch service not configured'
      : undefined,
    refetch: () => void load(),
    getPortStatus,
    enablePort,
    disablePort,
    setPortVLAN,
  };
}

interface PortListing {
  switchName: string;
  ports: SwitchPortStatus[] | undefined;
  error: Error | undefined;
}
