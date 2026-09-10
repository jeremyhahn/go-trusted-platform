'use client';

import * as React from 'react';

import type { GatewaySnapshot } from 'trusted-platform-sdk';

/**
 * ReportedGateway is one gatewayd's telemetry snapshot as the control
 * plane caches it: identity and health, plus the datapath sections its
 * services report — BGP sessions with their BFD state, tunnels, uplink
 * policy routes, the host filter, NAT and the base OVS pipeline (#594).
 *
 * The shape lives in the SDK (`GatewaySnapshot`) so the WebUI and any
 * other consumer read the same contract. Field names are snake_case
 * because this surface is the control-plane telemetry cache, which
 * serialises the Go struct directly rather than going through
 * protojson's camelCase mapping.
 */
export type ReportedGateway = GatewaySnapshot;

export interface UseReportedGatewaysOptions {
  /**
   * Skip fetching entirely. Used by pages that only need the fleet view
   * in one branch (the PXE page shows it only when PXE is absent here),
   * so the request is not issued on nodes that do serve the surface.
   */
  enabled?: boolean;
  /**
   * Poll interval in milliseconds. Omit or pass 0 to fetch once.
   */
  refreshMs?: number;
}

export interface UseReportedGatewaysResult {
  gateways: ReportedGateway[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
}

/**
 * useReportedGateways reads /api/v1/gateway/state — the control-plane
 * surface each gatewayd POSTs its telemetry into.
 *
 * This is deliberately independent of the GatewayService gRPC calls
 * behind `useGateway()`: the fleet data flows whether or not THIS node
 * runs a local gateway service, which is exactly what makes it the
 * right content for a control plane. Both the Gateway page and the PXE
 * page render slices of it, so it lives here rather than being copied
 * into each.
 *
 * The endpoint has no SDK service method yet (the SDK's GatewayService
 * covers the gRPC-backed local surface only), so the fetch is direct.
 * Session auth is cookie-based, matching the SDK's ApiClient.
 */
export function useReportedGateways(
  options: UseReportedGatewaysOptions = {}
): UseReportedGatewaysResult {
  const { enabled = true, refreshMs = 0 } = options;

  const [gateways, setGateways] = React.useState<ReportedGateway[]>([]);
  const [inFlight, setInFlight] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  // Loading covers both the window before the first fetch has landed
  // and any request in flight. Deriving it rather than seeding a state
  // from `enabled` matters for the PXE page, which only enables the
  // hook once it knows PXE is absent: a state seeded false would paint
  // "no gateways have reported" for one frame before the effect ran.
  const isLoading = enabled && (inFlight || !loaded);

  // Guards state updates from a request that is still in flight when
  // the page unmounts — the Gateway page polls, so navigating away
  // mid-request is the common case, not the edge one.
  const mounted = React.useRef(true);
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
    setInFlight(true);
    setError(null);
    try {
      const res = await fetch('/api/v1/gateway/state', { credentials: 'include' });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const body = await res.json();
      if (mounted.current) {
        setGateways(body.payload?.gateways ?? body.gateways ?? []);
      }
    } catch (e: unknown) {
      if (mounted.current) {
        setError(e instanceof Error ? e.message : String(e));
      }
    } finally {
      if (mounted.current) {
        setInFlight(false);
        setLoaded(true);
      }
    }
  }, [enabled]);

  React.useEffect(() => {
    if (!enabled) {
      return;
    }
    void refetch();
    if (!refreshMs) {
      return;
    }
    const id = setInterval(() => void refetch(), refreshMs);
    return () => clearInterval(id);
  }, [enabled, refetch, refreshMs]);

  return { gateways, isLoading, error, refetch };
}
