import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';

const gateway = {
  getPerfFlows: vi.fn(),
  getPerfDatapath: vi.fn(),
  getPerfConntrack: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => ({ gateway }),
}));

import { counterEntries, useGatewayPerf } from './use-gateway-perf';

describe('counterEntries', () => {
  it('lists scalar fields with uint64 strings parsed', () => {
    expect(
      counterEntries({ code: 200, success: true, payload: { flowCount: '12', bridge: 'br-int', hits: 3 } })
    ).toEqual([
      ['flowCount', 12],
      ['bridge', 'br-int'],
      ['hits', 3],
    ]);
  });

  it('keeps a uint64 beyond 2^53 as its exact string and skips nested values', () => {
    expect(counterEntries({ bytes: '18446744073709551615', zones: [{ zone: 1 }] })).toEqual([
      ['bytes', '18446744073709551615'],
    ]);
  });

  it('returns no entries for a missing payload', () => {
    expect(counterEntries(undefined)).toEqual([]);
  });
});

describe('useGatewayPerf', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    gateway.getPerfFlows.mockResolvedValue({
      success: true,
      data: { code: 200, success: true, payload: { flowCount: '5' } },
    });
    gateway.getPerfDatapath.mockResolvedValue({ success: false, error: { message: 'no bridge' } });
    gateway.getPerfConntrack.mockResolvedValue({ success: true, data: { entries: '9' } });
  });

  it('loads all three cards on mount, each with its own error', async () => {
    const { result } = renderHook(() => useGatewayPerf());
    await waitFor(() => expect(result.current.conntrack.loading).toBe(false));
    await waitFor(() => expect(result.current.flows.loading).toBe(false));
    await waitFor(() => expect(result.current.datapath.loading).toBe(false));
    expect(result.current.flows.data).toEqual({ flowCount: '5' });
    expect(result.current.datapath.error?.message).toBe('no bridge');
    expect(result.current.conntrack.data).toEqual({ entries: '9' });
  });

  it('passes the bridge and zone filters to the SDK', async () => {
    const { result } = renderHook(() => useGatewayPerf());
    await waitFor(() => expect(result.current.conntrack.loading).toBe(false));
    await act(async () => {
      await result.current.loadDatapath('br-int');
      await result.current.loadConntrack(7);
      await result.current.runFlows();
    });
    expect(gateway.getPerfDatapath).toHaveBeenLastCalledWith('br-int');
    expect(gateway.getPerfConntrack).toHaveBeenLastCalledWith(7);
    expect(gateway.getPerfFlows).toHaveBeenCalledTimes(2);
  });
});
