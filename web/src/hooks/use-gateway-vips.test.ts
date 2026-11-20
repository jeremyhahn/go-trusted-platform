import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';

const gateway = {
  listVIPs: vi.fn(),
  getVIP: vi.fn(),
  addVIP: vi.fn(),
  removeVIP: vi.fn(),
  setVIPBackends: vi.fn(),
  getLBStatus: vi.fn(),
  getNAT64Status: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => ({ gateway }),
}));

import { normalizeVIP, payloadOf, toUint64, useGatewayVIPs } from './use-gateway-vips';

const wireVIP = {
  vip: {
    address: '198.51.100.20',
    port: 8443,
    protocol: 'tcp',
    algorithm: 'maglev',
    backends: [{ address: '10.0.0.11', port: 443, weight: 1 }],
  },
  ctZone: '4096',
  groupId: '18446744073709551615',
  backends: [{ backend: { address: '10.0.0.11', port: 443, weight: 1 }, healthy: true }],
};

describe('payloadOf', () => {
  it('unwraps the web-service {code, success, payload} envelope', () => {
    expect(payloadOf({ code: 200, success: true, payload: { vips: [] } })).toEqual({ vips: [] });
  });

  it('passes a bare daemon payload through', () => {
    expect(payloadOf({ vips: [] })).toEqual({ vips: [] });
    expect(payloadOf(undefined)).toBeUndefined();
  });
});

describe('toUint64', () => {
  it('parses protojson uint64 strings and plain numbers', () => {
    expect(toUint64('4096')).toBe(4096);
    expect(toUint64(7)).toBe(7);
    expect(toUint64(undefined)).toBeUndefined();
    expect(toUint64('not-a-number')).toBeUndefined();
  });

  it('keeps a value beyond 2^53 as its exact string', () => {
    expect(toUint64('18446744073709551615')).toBe('18446744073709551615');
  });
});

describe('normalizeVIP', () => {
  it('flattens a VIPStatus into a row', () => {
    expect(normalizeVIP(wireVIP)).toEqual({
      address: '198.51.100.20',
      port: 8443,
      protocol: 'tcp',
      algorithm: 'maglev',
      ctZone: 4096,
      groupId: '18446744073709551615',
      backends: [{ address: '10.0.0.11', port: 443, weight: 1, healthy: true }],
    });
  });

  it('falls back to the configured backends when no health is reported', () => {
    const row = normalizeVIP({ vip: wireVIP.vip });
    expect(row.backends).toEqual([{ address: '10.0.0.11', port: 443, weight: 1, healthy: undefined }]);
  });
});

describe('useGatewayVIPs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    gateway.listVIPs.mockResolvedValue({
      success: true,
      data: { code: 200, success: true, payload: { vips: [wireVIP] } },
    });
    gateway.getLBStatus.mockResolvedValue({ success: true, data: { vipCount: '1' } });
    gateway.getNAT64Status.mockResolvedValue({ success: false, error: { message: 'not running' } });
  });

  it('lists VIPs from an enveloped response', async () => {
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.error).toBeUndefined();
    expect(result.current.vips).toHaveLength(1);
    expect(result.current.vips[0].address).toBe('198.51.100.20');
    expect(result.current.vips[0].ctZone).toBe(4096);
  });

  it('reports each status card on its own', async () => {
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.lbStatus).toEqual({ vipCount: '1' });
    expect(result.current.lbError).toBeUndefined();
    expect(result.current.nat64Status).toBeUndefined();
    expect(result.current.nat64Error?.message).toBe('not running');
  });

  it('surfaces a failed list as an error', async () => {
    gateway.listVIPs.mockResolvedValue({ success: false, error: { message: 'boom' } });
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.vips).toEqual([]);
    expect(result.current.error?.message).toBe('boom');
  });

  it('adds, removes and sets backends, then reloads', async () => {
    gateway.addVIP.mockResolvedValue({ success: true, data: {} });
    gateway.removeVIP.mockResolvedValue({ success: true, data: {} });
    gateway.setVIPBackends.mockResolvedValue({ success: true, data: {} });
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    const vip = { address: '198.51.100.21', port: 80, protocol: 'tcp', backends: [] };
    await act(async () => {
      await result.current.addVIP(vip);
      await result.current.removeVIP('198.51.100.21', 80, 'tcp');
      await result.current.setVIPBackends({ ...vip, backends: [{ address: '10.0.0.1', port: 80 }] });
    });
    expect(gateway.addVIP).toHaveBeenCalledWith(vip);
    expect(gateway.removeVIP).toHaveBeenCalledWith('198.51.100.21', 80, 'tcp');
    expect(gateway.setVIPBackends).toHaveBeenCalledWith({
      ...vip,
      backends: [{ address: '10.0.0.1', port: 80 }],
    });
    expect(gateway.listVIPs.mock.calls.length).toBeGreaterThanOrEqual(4);
  });

  it('throws a failed mutation so the caller can show it', async () => {
    gateway.removeVIP.mockResolvedValue({ success: false, error: { message: 'not found' } });
    const { result } = renderHook(() => useGatewayVIPs());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await expect(result.current.removeVIP('198.51.100.20', 8443, 'tcp')).rejects.toThrow('not found');
  });
});
