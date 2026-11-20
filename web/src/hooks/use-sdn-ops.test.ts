import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sdn = {
  flushFlows: vi.fn(),
  getFlowStats: vi.fn(),
  deletePolicy: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  useSDN: () => sdn,
}));

import { useSDNOps } from './use-sdn-ops';

beforeEach(() => {
  sdn.flushFlows.mockReset();
  sdn.getFlowStats.mockReset();
  sdn.deletePolicy.mockReset();
});

afterEach(() => {
  cleanup();
});

describe('useSDNOps.flushFlows', () => {
  it('flushes the bridge through the SDK and returns the deleted count', async () => {
    sdn.flushFlows.mockResolvedValue({ success: true, data: { status: 'SDN_STATUS_SUCCESS', deletedCount: 4 } });
    const { result } = renderHook(() => useSDNOps('br0'));

    let count: number | null = null;
    await act(async () => {
      count = await result.current.flushFlows('FLOW_TABLE_1');
    });

    expect(sdn.flushFlows).toHaveBeenCalledWith({ bridgeId: 'br0', table: 'FLOW_TABLE_1' });
    expect(count).toBe(4);
    expect(result.current.error).toBeNull();
    expect(result.current.pending).toBeNull();
  });

  it('reports the server error and returns null', async () => {
    sdn.flushFlows.mockResolvedValue({ success: false, error: { message: 'bridge not found' } });
    const { result } = renderHook(() => useSDNOps('br0'));

    let count: number | null = 0;
    await act(async () => {
      count = await result.current.flushFlows();
    });

    expect(count).toBeNull();
    expect(result.current.error).toBe('bridge not found');
  });

  it('does not call the SDK without a bridge', async () => {
    const { result } = renderHook(() => useSDNOps(''));

    let count: number | null = 0;
    await act(async () => {
      count = await result.current.flushFlows();
    });

    expect(count).toBeNull();
    expect(sdn.flushFlows).not.toHaveBeenCalled();
    expect(result.current.error).toBe('Select a bridge first');
  });
});

describe('useSDNOps.getFlowStats', () => {
  it('reads one flow statistics through the SDK', async () => {
    const stats = { packetCount: '12', byteCount: '960', durationSeconds: 3 };
    sdn.getFlowStats.mockResolvedValue({ success: true, data: { stats } });
    const { result } = renderHook(() => useSDNOps('br0'));

    let got: unknown = null;
    await act(async () => {
      got = await result.current.getFlowStats('f-1');
    });

    expect(sdn.getFlowStats).toHaveBeenCalledWith('br0', 'f-1');
    expect(got).toEqual(stats);
  });

  it('returns null and an error when the call throws', async () => {
    sdn.getFlowStats.mockRejectedValue(new Error('network down'));
    const { result } = renderHook(() => useSDNOps('br0'));

    let got: unknown = 'x';
    await act(async () => {
      got = await result.current.getFlowStats('f-1');
    });

    expect(got).toBeNull();
    expect(result.current.error).toBe('network down');
  });
});

describe('useSDNOps.deletePolicy', () => {
  it('deletes the policy through the SDK', async () => {
    sdn.deletePolicy.mockResolvedValue({ success: true, data: {} });
    const { result } = renderHook(() => useSDNOps('br0'));

    let ok = false;
    await act(async () => {
      ok = await result.current.deletePolicy('pol-1');
    });

    expect(sdn.deletePolicy).toHaveBeenCalledWith('pol-1');
    expect(ok).toBe(true);
  });

  it('returns false with the server error', async () => {
    sdn.deletePolicy.mockResolvedValue({ success: false, error: { message: 'policy not found' } });
    const { result } = renderHook(() => useSDNOps(''));

    let ok = true;
    await act(async () => {
      ok = await result.current.deletePolicy('pol-1');
    });

    expect(ok).toBe(false);
    expect(result.current.error).toBe('policy not found');
  });
});
