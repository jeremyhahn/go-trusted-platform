'use client';

/**
 * Gateway operations for the gateway page (#2051): SetGatewayMode, the
 * snapshot lookup (GetGatewaySnapshot), the admitted-VTEP list and lookup
 * (ListGatewayAdmittedVTEPs, GetGatewayAdmittedVTEP) and the IPAM pool
 * lookup and delete (GetIPAMPool, DeleteIPAMPool), all through the SDK
 * gateway service.
 *
 * Each call resolves to a result rather than throwing. A node that runs
 * no gatewayd answers the local gateway RPCs with the typed 503 "not
 * configured"; the result marks that, so the page can disable the control
 * and show the reason.
 */

import { useCallback, useMemo } from 'react';
import { isServiceNotConfigured, useGateway } from 'trusted-platform-sdk';
import type {
  ApiResponse,
  GatewaySnapshot,
  GetGatewayAdmittedVTEPResponse,
  IPAMPoolRecord,
  ListGatewayAdmittedVTEPsResponse,
  SetGatewayModeResponse,
} from 'trusted-platform-sdk';

export type GatewayOpResult<T> =
  | { ok: true; data: T }
  | { ok: false; error: string; notConfigured: boolean };

interface WireError {
  code?: string;
  message?: string;
  status?: number;
  statusCode?: number;
}

/** True when the error is the typed 503 a node without gatewayd answers. */
export function gatewayNotConfigured(error: unknown): boolean {
  if (error === null || error === undefined) return false;
  try {
    if (isServiceNotConfigured(error as never)) return true;
  } catch {
    // Fall through to the shape checks below.
  }
  const e = error as WireError;
  if (e.status === 503 || e.statusCode === 503) return true;
  if (typeof e.code === 'string' && /UNAVAILABLE|NOT_CONFIGURED/i.test(e.code)) return true;
  return typeof e.message === 'string' && /not configured|not run/i.test(e.message);
}

async function run<T>(what: string, call: () => Promise<ApiResponse<T>>): Promise<GatewayOpResult<T>> {
  try {
    const response = await call();
    if (response.success === false) {
      const error = response.error as WireError | undefined;
      return {
        ok: false,
        error: error?.message || `${what} failed`,
        notConfigured: gatewayNotConfigured(error),
      };
    }
    return { ok: true, data: response.data as T };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      notConfigured: gatewayNotConfigured(err),
    };
  }
}

export interface UseGatewayOpsResult {
  setMode: (modes: number) => Promise<GatewayOpResult<SetGatewayModeResponse>>;
  getSnapshot: (gatewayId: string) => Promise<GatewayOpResult<GatewaySnapshot>>;
  listAdmittedVTEPs: (gatewayId?: string) => Promise<GatewayOpResult<ListGatewayAdmittedVTEPsResponse>>;
  getAdmittedVTEP: (vtep: string, gatewayId?: string) => Promise<GatewayOpResult<GetGatewayAdmittedVTEPResponse>>;
  getIPAMPool: (id: string) => Promise<GatewayOpResult<IPAMPoolRecord>>;
  deleteIPAMPool: (id: string) => Promise<GatewayOpResult<void>>;
}

export function useGatewayOps(): UseGatewayOpsResult {
  const gateway = useGateway();

  const setMode = useCallback(
    (modes: number) => run('SetGatewayMode', () => gateway.setMode({ modes })),
    [gateway]
  );
  const getSnapshot = useCallback(
    (gatewayId: string) => run('GetGatewaySnapshot', () => gateway.getState(gatewayId)),
    [gateway]
  );
  const listAdmittedVTEPs = useCallback(
    (gatewayId?: string) =>
      run('ListGatewayAdmittedVTEPs', () => gateway.listAdmittedVTEPs(gatewayId)),
    [gateway]
  );
  const getAdmittedVTEP = useCallback(
    (vtep: string, gatewayId?: string) =>
      run('GetGatewayAdmittedVTEP', () => gateway.getAdmittedVTEP(vtep, gatewayId)),
    [gateway]
  );
  const getIPAMPool = useCallback(
    (id: string) => run('GetIPAMPool', () => gateway.getIPAMPool(id)),
    [gateway]
  );
  const deleteIPAMPool = useCallback(
    (id: string) => run('DeleteIPAMPool', () => gateway.deleteIPAMPool(id)),
    [gateway]
  );

  return useMemo(
    () => ({ setMode, getSnapshot, listAdmittedVTEPs, getAdmittedVTEP, getIPAMPool, deleteIPAMPool }),
    [setMode, getSnapshot, listAdmittedVTEPs, getAdmittedVTEP, getIPAMPool, deleteIPAMPool]
  );
}
