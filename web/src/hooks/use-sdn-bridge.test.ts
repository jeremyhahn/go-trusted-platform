import { describe, it, expect, vi, afterEach } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useSDNBridge } from './use-sdn-bridge';

type Reply = { success: boolean; data?: unknown; error?: { message: string } };

interface Pending {
  kind: 'bridge' | 'ports';
  id: string;
  resolve: (r: Reply) => void;
}

const pending: Pending[] = [];

function defer(kind: Pending['kind'], id: string): Promise<Reply> {
  return new Promise<Reply>((resolve) => {
    pending.push({ kind, id, resolve });
  });
}

const sdn = {
  getBridge: vi.fn((id: string) => defer('bridge', id)),
  listPorts: vi.fn((opts: { bridgeId: string }) => defer('ports', opts.bridgeId)),
  listPolicies: vi.fn(async () => ({ success: true, data: { policies: [] } })),
};

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useSDN: () => sdn,
}));

function find(kind: Pending['kind'], id: string): Pending {
  const p = pending.find((x) => x.kind === kind && x.id === id);
  if (!p) {
    throw new Error(`no pending ${kind} request for ${id}`);
  }
  return p;
}

afterEach(() => {
  pending.length = 0;
  vi.clearAllMocks();
});

describe('useSDNBridge across a bridge change', () => {
  it("ignores bridge A's late response after a change to B", async () => {
    const { result, rerender } = renderHook(({ id }) => useSDNBridge(id), {
      initialProps: { id: 'br-a' },
    });
    await waitFor(() => expect(pending).toHaveLength(2));
    rerender({ id: 'br-b' });
    await waitFor(() => expect(pending).toHaveLength(4));

    await act(async () => {
      find('bridge', 'br-b').resolve({ success: true, data: { bridge: { id: 'br-b' } } });
      find('ports', 'br-b').resolve({ success: true, data: { ports: [{ name: 'pb' }] } });
    });
    await act(async () => {
      find('bridge', 'br-a').resolve({ success: true, data: { bridge: { id: 'br-a' } } });
      find('ports', 'br-a').resolve({ success: true, data: { ports: [{ name: 'pa' }] } });
    });

    expect(result.current.bridge?.id).toBe('br-b');
    expect(result.current.ports.map((p) => (p as { name?: string }).name)).toEqual(['pb']);
    expect(result.current.loading).toBe(false);
  });

  it('is loading after a bridge change until the new bridge lands', async () => {
    const { result, rerender } = renderHook(({ id }) => useSDNBridge(id), {
      initialProps: { id: 'br-a' },
    });
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () => {
      find('bridge', 'br-a').resolve({ success: true, data: { bridge: { id: 'br-a' } } });
      find('ports', 'br-a').resolve({ success: true, data: { ports: [] } });
    });
    expect(result.current.loading).toBe(false);
    expect(result.current.bridge?.id).toBe('br-a');

    rerender({ id: 'br-b' });
    await waitFor(() => expect(pending).toHaveLength(4));
    expect(result.current.loading).toBe(true);
    expect(result.current.bridge).toBeNull();

    await act(async () => {
      find('bridge', 'br-b').resolve({ success: true, data: { bridge: { id: 'br-b' } } });
    });
    expect(result.current.loading).toBe(false);
    expect(result.current.bridge?.id).toBe('br-b');
  });

  it('reports a failed bridge reply', async () => {
    const { result } = renderHook(() => useSDNBridge('br-a'));
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () => {
      find('bridge', 'br-a').resolve({ success: false, error: { message: 'boom' } });
    });
    expect(result.current.bridgeError).toBe('boom');
    expect(result.current.bridge).toBeNull();
    expect(result.current.loading).toBe(false);
  });
});
