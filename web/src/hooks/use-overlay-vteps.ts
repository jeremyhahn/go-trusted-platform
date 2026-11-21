'use client';

import * as React from 'react';
import { useApi, useOverlay } from 'trusted-platform-sdk';
import type {
  GetOverlayStatusResponse,
  ListRemoteMACsResponse,
  ListTunnelsResponse,
  ListVNIsResponse,
  ListVTEPsResponse,
  OverlayStatus,
  TunnelInfo,
  VTEPInfo,
} from 'trusted-platform-sdk';

/** The client resolves failed requests as { success: false }; turn them into a rejection. */
function failure(message: string | undefined): Error {
  return new Error(message || 'Request failed');
}

/**
 * Overlay data for the VTEPs page (#1722, #2059): the overlay status, VTEPs,
 * VNIs, tunnels and remote MACs, plus
 * the per-item reads and the destructive actions the page offers.
 */
export function useOverlayVteps() {
  const overlay = useOverlay();

  const vteps = useApi<ListVTEPsResponse>(() => overlay.listVTEPs(), []);
  const vnis = useApi<ListVNIsResponse>(() => overlay.listVNIs(), []);
  const tunnels = useApi<ListTunnelsResponse>(() => overlay.listTunnels(), []);
  const macs = useApi<ListRemoteMACsResponse>(() => overlay.listRemoteMACs(), []);
  const status = useApi<GetOverlayStatusResponse>(() => overlay.getStatus(), []);

  const getVTEP = React.useCallback(
    async (nodeId: string): Promise<VTEPInfo | undefined> => {
      const res = await overlay.getVTEP(nodeId);
      if (!res.success) throw failure(res.error?.message);
      return res.data?.vtep;
    },
    [overlay]
  );

  const getTunnelStats = React.useCallback(
    async (remoteVtep: string, vni: number): Promise<TunnelInfo | undefined> => {
      const res = await overlay.getTunnelStats({ remoteVtep, vni });
      if (!res.success) throw failure(res.error?.message);
      return res.data?.tunnel;
    },
    [overlay]
  );

  const refetchVteps = vteps.refetch;
  const refetchVnis = vnis.refetch;
  const refetchTunnels = tunnels.refetch;
  const refetchMacs = macs.refetch;
  const refetchStatus = status.refetch;

  const deleteVNI = React.useCallback(
    async (vni: number) => {
      const res = await overlay.deleteVNI(vni);
      if (!res.success) throw failure(res.error?.message);
      // The server removes every remote MAC of a deleted VNI as well.
      await refetchVnis();
      await refetchMacs();
      await refetchStatus();
    },
    [overlay, refetchVnis, refetchMacs, refetchStatus]
  );

  const forgetMAC = React.useCallback(
    async (mac: string, vni: number) => {
      const res = await overlay.forgetMAC({ mac, vni });
      if (!res.success) throw failure(res.error?.message);
      await refetchMacs();
      await refetchStatus();
    },
    [overlay, refetchMacs, refetchStatus]
  );

  const refetchAll = React.useCallback(() => {
    void refetchStatus();
    void refetchVteps();
    void refetchVnis();
    void refetchTunnels();
    void refetchMacs();
  }, [refetchStatus, refetchVteps, refetchVnis, refetchTunnels, refetchMacs]);

  return {
    status: status.data?.status as OverlayStatus | undefined,
    statusError: status.error,
    vteps: vteps.data?.vteps ?? [],
    vnis: vnis.data?.vnis ?? [],
    tunnels: tunnels.data?.tunnels ?? [],
    macs: macs.data?.macs ?? [],
    // The status is left out on purpose: a node without an overlay
    // controller still shows the tables.
    isLoading: vteps.isLoading || vnis.isLoading || tunnels.isLoading || macs.isLoading,
    vtepsError: vteps.error,
    vnisError: vnis.error,
    tunnelsError: tunnels.error,
    macsError: macs.error,
    refetchAll,
    getVTEP,
    getTunnelStats,
    deleteVNI,
    forgetMAC,
  };
}
