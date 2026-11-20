import * as React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';

const overlay = {
  getStatus: vi.fn(),
  listVTEPs: vi.fn(),
  getVTEP: vi.fn(),
  listVNIs: vi.fn(),
  deleteVNI: vi.fn(),
  listTunnels: vi.fn(),
  getTunnelStats: vi.fn(),
  listRemoteMACs: vi.fn(),
  forgetMAC: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  useOverlay: () => overlay,
  // A minimal useApi: run the call on mount and on refetch, keep data/error.
  useApi: <T,>(call: () => Promise<{ success: boolean; data?: T; error?: { message?: string } }>) => {
    const [data, setData] = React.useState<T | undefined>(undefined);
    const [error, setError] = React.useState<Error | null>(null);
    const [isLoading, setLoading] = React.useState(true);
    const callRef = React.useRef(call);
    callRef.current = call;
    const refetch = React.useCallback(async () => {
      setLoading(true);
      const res = await callRef.current();
      if (res.success) {
        setData(res.data);
        setError(null);
      } else {
        setError(new Error(res.error?.message || 'Request failed'));
      }
      setLoading(false);
    }, []);
    React.useEffect(() => {
      void refetch();
    }, [refetch]);
    return { data, error, isLoading, refetch };
  },
}));

import { useOverlayVteps } from './use-overlay-vteps';

const STATUS = {
  nodeId: 'node-a',
  vtepIp: '10.0.0.1',
  vtepCount: 3,
  vniCount: 2,
  tunnelCount: 4,
  remoteMacCount: 7,
  healthy: true,
};

function okLists() {
  overlay.listVTEPs.mockResolvedValue({ success: true, data: { vteps: [{ nodeId: 'node-a', ip: '10.0.0.1', healthy: true }] } });
  overlay.listVNIs.mockResolvedValue({ success: true, data: { vnis: [] } });
  overlay.listTunnels.mockResolvedValue({ success: true, data: { tunnels: [] } });
  overlay.listRemoteMACs.mockResolvedValue({ success: true, data: { macs: [] } });
}

afterEach(() => {
  vi.clearAllMocks();
});

describe('useOverlayVteps: GetOverlayStatus (#2059)', () => {
  it('loads the overlay status through overlay.getStatus', async () => {
    okLists();
    overlay.getStatus.mockResolvedValue({ success: true, data: { status: STATUS } });

    const { result } = renderHook(() => useOverlayVteps());

    await waitFor(() => expect(result.current.status).toEqual(STATUS));
    expect(overlay.getStatus).toHaveBeenCalledTimes(1);
    expect(result.current.statusError).toBeNull();
    expect(result.current.vteps).toHaveLength(1);
  });

  it('surfaces a status failure as statusError and leaves status undefined', async () => {
    okLists();
    overlay.getStatus.mockResolvedValue({ success: false, error: { message: 'overlay disabled' } });

    const { result } = renderHook(() => useOverlayVteps());

    await waitFor(() => expect(result.current.statusError?.message).toBe('overlay disabled'));
    expect(result.current.status).toBeUndefined();
  });

  it('refetchAll reads the status again', async () => {
    okLists();
    overlay.getStatus.mockResolvedValue({ success: true, data: { status: STATUS } });

    const { result } = renderHook(() => useOverlayVteps());
    await waitFor(() => expect(result.current.status).toEqual(STATUS));

    overlay.getStatus.mockResolvedValue({ success: true, data: { status: { ...STATUS, healthy: false } } });
    act(() => {
      result.current.refetchAll();
    });

    await waitFor(() => expect(result.current.status?.healthy).toBe(false));
    expect(overlay.getStatus).toHaveBeenCalledTimes(2);
  });

  it('forgetMAC sends the MAC and VNI and rejects with the server message', async () => {
    okLists();
    overlay.getStatus.mockResolvedValue({ success: true, data: { status: STATUS } });
    overlay.forgetMAC.mockResolvedValue({ success: false, error: { message: 'unknown MAC' } });

    const { result } = renderHook(() => useOverlayVteps());
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await expect(result.current.forgetMAC('02:00:5e:10:20:30', 900)).rejects.toThrow('unknown MAC');
    expect(overlay.forgetMAC).toHaveBeenCalledWith({ mac: '02:00:5e:10:20:30', vni: 900 });
  });
});
