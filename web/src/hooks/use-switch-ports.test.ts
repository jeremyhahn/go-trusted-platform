import { describe, it, expect, vi, afterEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useSwitchPorts } from './use-switch-ports';

type ListReply = { success: boolean; data?: Array<{ port: string }> };

interface Pending {
  switchName: string;
  resolve: (r: ListReply) => void;
}

const pending: Pending[] = [];

const switches = {
  listPorts: vi.fn(
    (switchName: string) =>
      new Promise<ListReply>((resolve) => {
        pending.push({ switchName, resolve });
      })
  ),
  getPortStatus: vi.fn(),
  enablePort: vi.fn(),
  disablePort: vi.fn(async () => ({ success: true, data: { ok: true } })),
  setPortVLAN: vi.fn(async () => ({ success: true, data: { ok: true } })),
};
const client = { switches };

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  usePlatformClient: () => client,
}));

function ports(names: string[]): ListReply {
  return { success: true, data: names.map((port) => ({ port })) };
}

afterEach(() => {
  pending.length = 0;
  vi.clearAllMocks();
});

describe('useSwitchPorts across a switch change', () => {
  it("hides switch A's ports after a change to B and ignores A's late response", async () => {
    const { result, rerender } = renderHook(({ name }) => useSwitchPorts(name), {
      initialProps: { name: 'sw-a' },
    });
    await waitFor(() => expect(pending).toHaveLength(1));
    await act(async () => {
      pending[0].resolve(ports(['a1']));
    });
    expect(result.current.ports.map((p) => p.port)).toEqual(['a1']);
    expect(result.current.isLoading).toBe(false);

    // A second listing of A is in flight when the switch changes.
    act(() => {
      result.current.refetch();
    });
    await waitFor(() => expect(pending).toHaveLength(2));

    rerender({ name: 'sw-b' });
    await waitFor(() => expect(pending).toHaveLength(3));
    expect(pending[2].switchName).toBe('sw-b');
    expect(result.current.ports).toEqual([]);
    expect(result.current.isLoading).toBe(true);
    await expect(result.current.disablePort('a1')).rejects.toThrow();
    await expect(result.current.setPortVLAN('a1', 10)).rejects.toThrow();
    expect(switches.disablePort).not.toHaveBeenCalled();
    expect(switches.setPortVLAN).not.toHaveBeenCalled();

    // A's late response must not show under B.
    await act(async () => {
      pending[1].resolve(ports(['a-late']));
    });
    expect(result.current.ports).toEqual([]);
    expect(result.current.isLoading).toBe(true);

    await act(async () => {
      pending[2].resolve(ports(['b1']));
    });
    expect(result.current.ports.map((p) => p.port)).toEqual(['b1']);
    expect(result.current.isLoading).toBe(false);

    await act(async () => {
      await result.current.disablePort('b1');
    });
    expect(switches.disablePort).toHaveBeenCalledWith('sw-b', 'b1');
  });

  it("keeps B's ports when A's response lands after B's", async () => {
    const { result, rerender } = renderHook(({ name }) => useSwitchPorts(name), {
      initialProps: { name: 'sw-a' },
    });
    await waitFor(() => expect(pending).toHaveLength(1));
    rerender({ name: 'sw-b' });
    await waitFor(() => expect(pending).toHaveLength(2));

    await act(async () => {
      pending[1].resolve(ports(['b1']));
    });
    await act(async () => {
      pending[0].resolve(ports(['a1']));
    });
    expect(result.current.ports.map((p) => p.port)).toEqual(['b1']);
    expect(result.current.isLoading).toBe(false);
  });
});
