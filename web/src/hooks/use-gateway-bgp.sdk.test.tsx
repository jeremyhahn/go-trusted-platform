import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// One stable client: a new object per render would re-run the hook's effects.
const gateway = {
  listBGPPeers: vi.fn(),
  listAnnouncedPrefixes: vi.fn(),
  listAllocations: vi.fn(),
  announcePrefix: vi.fn(),
  withdrawPrefix: vi.fn(),
  allocateIP: vi.fn(),
  releaseIP: vi.fn(),
};
const client = { gateway };

vi.mock('trusted-platform-sdk', () => ({ usePlatformClient: () => client }));

import { useGatewayBgp } from './use-gateway-bgp';

function ok(data: unknown) {
  return { success: true, data };
}

const peer = { address: '10.0.0.2', asn: 64513, state: 'established', prefixesReceived: 4 };
const prefix = { prefix: '10.1.0.0/24', nextHop: '10.0.0.1' };
const allocation = { ip: '10.0.0.5', poolId: 'p1', hostname: 'h' };

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('the gateway hook must not call fetch');
    })
  );
  gateway.listBGPPeers.mockResolvedValue(ok({ peers: [peer] }));
  gateway.listAnnouncedPrefixes.mockResolvedValue(ok({ prefixes: [prefix] }));
  gateway.listAllocations.mockResolvedValue(ok({ allocations: [allocation] }));
  gateway.announcePrefix.mockResolvedValue(ok({}));
  gateway.withdrawPrefix.mockResolvedValue(ok({}));
  gateway.allocateIP.mockResolvedValue(ok({ allocation }));
  gateway.releaseIP.mockResolvedValue(ok({}));
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

async function mounted() {
  const hook = renderHook(() => useGatewayBgp());
  await waitFor(() => expect(hook.result.current.isLoading).toBe(false));
  return hook;
}

describe('useGatewayBgp through PlatformClient.gateway', () => {
  it('loads peers, prefixes and allocations through client.gateway', async () => {
    const { result } = await mounted();
    expect(result.current.peers[0].asn).toBe(64513);
    expect(result.current.prefixes[0].nextHop).toBe('10.0.0.1');
    expect(result.current.allocations[0].poolId).toBe('p1');
    expect(result.current.errors).toEqual({ peers: null, prefixes: null, allocations: null });
    expect(gateway.listAllocations).toHaveBeenCalled();
    expect(gateway.listAllocations.mock.calls[0][0]).toBeUndefined();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('a failed section is that section\'s error', async () => {
    gateway.listBGPPeers.mockResolvedValue({
      success: false,
      error: { code: 'HTTP_503', message: 'bgp speaker not running', status: 503 },
    });
    const { result } = await mounted();
    expect(result.current.errors.peers).toBe('bgp speaker not running');
    expect(result.current.peers).toEqual([]);
    expect(result.current.prefixes[0].prefix).toBe('10.1.0.0/24');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('the mutations pass the SDK requests and refetch', async () => {
    const { result } = await mounted();

    gateway.listBGPPeers.mockClear();
    await act(async () => {
      await result.current.announcePrefix('10.1.0.0/24', '10.0.0.1');
    });
    expect(gateway.announcePrefix).toHaveBeenCalledWith({
      prefix: '10.1.0.0/24',
      nextHop: '10.0.0.1',
    });
    expect(gateway.listBGPPeers).toHaveBeenCalled();

    gateway.listBGPPeers.mockClear();
    await act(async () => {
      await result.current.withdrawPrefix('10.1.0.0/24');
    });
    expect(gateway.withdrawPrefix).toHaveBeenCalledWith({ prefix: '10.1.0.0/24' });
    expect(gateway.listBGPPeers).toHaveBeenCalled();

    gateway.listBGPPeers.mockClear();
    let got: unknown;
    await act(async () => {
      got = await result.current.allocateIP('p1', 'd1', 'h');
    });
    expect(gateway.allocateIP).toHaveBeenCalledWith({ poolId: 'p1', deviceId: 'd1', hostname: 'h' });
    expect(got).toEqual({ ip: '10.0.0.5', poolId: 'p1', deviceId: '', hostname: 'h', status: '' });
    expect(gateway.listBGPPeers).toHaveBeenCalled();

    gateway.listBGPPeers.mockClear();
    await act(async () => {
      await result.current.releaseIP('10.0.0.5');
    });
    expect(gateway.releaseIP).toHaveBeenCalledWith({ ip: '10.0.0.5' });
    expect(gateway.listBGPPeers).toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('a failed mutation throws the SDK error message', async () => {
    gateway.announcePrefix.mockResolvedValue({
      success: false,
      error: { code: 'HTTP_400', message: 'invalid prefix', status: 400 },
    });
    const { result } = await mounted();
    await expect(result.current.announcePrefix('x', '')).rejects.toThrow(/invalid prefix/);
    expect(fetch).not.toHaveBeenCalled();
  });
});
