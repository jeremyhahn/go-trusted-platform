import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';

const gateway = {
  listVIPs: vi.fn(),
  getLBStatus: vi.fn(),
};

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useGateway: () => gateway,
}));

import { useGatewayVIPs } from './use-gateway-vips';

const vip = {
  vip: {
    address: '10.0.0.5',
    port: 443,
    protocol: 'tcp',
    algorithm: 'hash',
    backends: [{ address: '10.0.1.1', port: 8443, weight: 1 }],
  },
  ctZone: 7,
  groupId: 3,
  backends: [{ backend: { address: '10.0.1.1', port: 8443, weight: 1 }, healthy: true }],
};

const lbStatus = {
  active: true,
  vipCount: 1,
  healthyBackends: 1,
  totalBackends: 1,
  lastReconcile: null,
};

describe('useGatewayVIPs', () => {
  beforeEach(() => {
    gateway.listVIPs.mockReset();
    gateway.getLBStatus.mockReset();
    gateway.listVIPs.mockResolvedValue({ success: true, data: { vips: [vip] } });
    gateway.getLBStatus.mockResolvedValue({ success: true, data: { status: lbStatus } });
  });

  it('loads the VIPs and the LB status on mount', async () => {
    const { result } = renderHook(() => useGatewayVIPs());

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.vips).toHaveLength(1);
    expect(result.current.lbStatus?.vipCount).toBe(1);
    expect(result.current.error).toBeNull();
    expect(gateway.listVIPs).toHaveBeenCalledTimes(1);
    expect(gateway.getLBStatus).toHaveBeenCalledTimes(1);
  });

  it('reports a refused list and leaves the VIPs empty', async () => {
    gateway.listVIPs.mockResolvedValue({
      success: false,
      error: { code: 'UNAVAILABLE', message: 'load balancer not configured' },
    });

    const { result } = renderHook(() => useGatewayVIPs());

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.error).toBe('load balancer not configured');
    expect(result.current.vips).toEqual([]);
  });

  it('reports a rejected status call', async () => {
    gateway.getLBStatus.mockRejectedValue(new Error('network down'));

    const { result } = renderHook(() => useGatewayVIPs());

    await waitFor(() => expect(result.current.isLoading).toBe(false));

    expect(result.current.error).toBe('network down');
  });

  it('refetch calls both reads again', async () => {
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(async () => {
      await result.current.refetch();
    });

    expect(gateway.listVIPs).toHaveBeenCalledTimes(2);
    expect(gateway.getLBStatus).toHaveBeenCalledTimes(2);
  });

  it('calls nothing when disabled', async () => {
    const { result } = renderHook(() => useGatewayVIPs({ enabled: false }));

    expect(result.current.isLoading).toBe(false);
    expect(gateway.listVIPs).not.toHaveBeenCalled();
    expect(gateway.getLBStatus).not.toHaveBeenCalled();
  });
});
