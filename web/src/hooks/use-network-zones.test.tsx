import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const sdn = {
  listNetworkZones: vi.fn(),
  createNetworkZone: vi.fn(),
  updateNetworkZone: vi.fn(),
  deleteNetworkZone: vi.fn(),
};

vi.mock('trusted-platform-sdk', async (importOriginal) => {
  const actual = await importOriginal<typeof import('trusted-platform-sdk')>();
  return { ...actual, useSDN: () => sdn };
});

import { useNetworkZones } from './use-network-zones';

const lab = { name: 'lab', offset: 30, services: ['dns'] };
const ok = <T,>(data: T) => ({ success: true, data });

beforeEach(() => {
  for (const fn of Object.values(sdn)) fn.mockReset();
  sdn.listNetworkZones.mockResolvedValue(ok({ zones: [lab], count: 1 }));
});

afterEach(() => cleanup());

describe('useNetworkZones', () => {
  it('lists the zones through SDNService.listNetworkZones', async () => {
    const { result } = renderHook(() => useNetworkZones());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(sdn.listNetworkZones).toHaveBeenCalledTimes(1);
    expect(result.current.zones).toEqual([lab]);
    expect(result.current.error).toBeUndefined();
  });

  it('creates, updates and deletes through the SDK and lists again after each', async () => {
    sdn.createNetworkZone.mockResolvedValue(ok({ ...lab, name: 'dmz' }));
    sdn.updateNetworkZone.mockResolvedValue(ok(lab));
    sdn.deleteNetworkZone.mockResolvedValue(ok({ deleted: true, restart_required: false }));
    const { result } = renderHook(() => useNetworkZones());
    await waitFor(() => expect(result.current.isLoading).toBe(false));

    await act(async () => {
      await result.current.createZone({ name: 'dmz', offset: 40 });
    });
    expect(sdn.createNetworkZone).toHaveBeenCalledWith({ name: 'dmz', offset: 40 });

    await act(async () => {
      await result.current.updateZone('lab', { offset: 31 });
    });
    expect(sdn.updateNetworkZone).toHaveBeenCalledWith('lab', { offset: 31 });

    await act(async () => {
      await result.current.deleteZone('lab');
    });
    expect(sdn.deleteNetworkZone).toHaveBeenCalledWith('lab');
    await waitFor(() => expect(sdn.listNetworkZones).toHaveBeenCalledTimes(4));
  });

  it('throws the server message when a mutation is refused', async () => {
    sdn.createNetworkZone.mockResolvedValue({ success: false, error: { message: 'zone exists' } });
    sdn.deleteNetworkZone.mockResolvedValue({ success: false, error: { message: 'built-in zone' } });
    const { result } = renderHook(() => useNetworkZones());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    await expect(result.current.createZone({ name: 'lab', offset: 30 })).rejects.toThrow('zone exists');
    await expect(result.current.deleteZone('mgmt')).rejects.toThrow('built-in zone');
  });

  it('surfaces a failed listing as an error with no zones', async () => {
    sdn.listNetworkZones.mockResolvedValue({ success: false, error: { message: 'sdn unavailable' } });
    const { result } = renderHook(() => useNetworkZones());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.zones).toEqual([]);
    expect(result.current.error?.message).toMatch(/sdn unavailable/);
  });
});
