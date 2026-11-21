'use client';

import * as React from 'react';

import { useGateway } from 'trusted-platform-sdk';
import type { LBStatus, VIPStatus } from 'trusted-platform-sdk';

export interface UseGatewayVIPsOptions {
  /** Skip fetching entirely. */
  enabled?: boolean;
}

export interface UseGatewayVIPsResult {
  vips: VIPStatus[];
  lbStatus: LBStatus | null;
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

/**
 * useGatewayVIPs reads the gateway load balancer through the SDK:
 * `client.gateway.listVIPs()` (GET /api/v1/gateway/lb/vips) and
 * `client.gateway.getLBStatus()` (GET /api/v1/gateway/lb/status), together,
 * on mount and on refetch (#2052).
 */
export function useGatewayVIPs(options: UseGatewayVIPsOptions = {}): UseGatewayVIPsResult {
  const { enabled = true } = options;
  const gateway = useGateway();

  const [vips, setVIPs] = React.useState<VIPStatus[]>([]);
  const [lbStatus, setLBStatus] = React.useState<LBStatus | null>(null);
  const [inFlight, setInFlight] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  // Loading covers the window before the first read lands and any read in
  // flight; derived so a disabled hook never reports loading.
  const isLoading = enabled && (inFlight || !loaded);

  const mounted = React.useRef(true);
  // A newer refetch supersedes an older one; a stale completion writes
  // nothing, so an older slower read cannot restore removed VIPs, stale
  // health or clear loading while the newest read is pending (#2163 Codex).
  const generation = React.useRef(0);
  React.useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refetch = React.useCallback(async () => {
    if (!enabled) {
      return;
    }
    const gen = ++generation.current;
    const isCurrent = () => mounted.current && gen === generation.current;
    setInFlight(true);
    setError(null);
    try {
      const [list, status] = await Promise.all([gateway.listVIPs(), gateway.getLBStatus()]);
      if (!isCurrent()) {
        return;
      }
      let firstError: string | null = null;
      if (list.error) {
        firstError = list.error.message;
        setVIPs([]);
      } else {
        setVIPs(list.data?.vips ?? []);
      }
      if (status.error) {
        firstError = firstError ?? status.error.message;
        setLBStatus(null);
      } else {
        setLBStatus(status.data?.status ?? null);
      }
      setError(firstError);
    } catch (e: unknown) {
      if (isCurrent()) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (isCurrent()) {
        setInFlight(false);
        setLoaded(true);
      }
    }
  }, [enabled, gateway]);

  React.useEffect(() => {
    if (!enabled) {
      return;
    }
    void refetch();
  }, [enabled, refetch]);

  return { vips, lbStatus, isLoading, error, refetch };
}
