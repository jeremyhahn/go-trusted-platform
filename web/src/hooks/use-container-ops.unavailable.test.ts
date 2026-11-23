import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SERVICE_NOT_CONFIGURED } from 'trusted-platform-sdk';

// #2045: a node without compute answers GetContainer with the structured
// not-configured 503; the hook flags it as unavailable rather than as a
// failed load, so the page can show the not-configured state.

interface Deferred {
  id: string;
  resolve: (value: unknown) => void;
}

const calls = vi.hoisted(() => ({
  get: [] as Deferred[],
  metrics: [] as Deferred[],
}));

const compute = vi.hoisted(() => ({
  getContainer: (id: string) =>
    new Promise((resolve) => {
      calls.get.push({ id, resolve });
    }),
  getContainerMetrics: (id: string) =>
    new Promise((resolve) => {
      calls.metrics.push({ id, resolve });
    }),
  execContainer: () => Promise.resolve({ success: true, data: {} }),
  attestContainer: () => Promise.resolve({ success: true, data: {} }),
  attestVM: vi.fn(),
  verifyVMAttestation: vi.fn(),
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useCompute: () => compute,
}));

import { useContainerOps } from './use-container-ops';

function settle(list: Deferred[], id: string, value: unknown): void {
  const i = list.findIndex((d) => d.id === id);
  if (i < 0) throw new Error(`no pending request for ${id}`);
  const [d] = list.splice(i, 1);
  d.resolve(value);
}

const containerOf = (id: string) => ({ success: true, data: { container: { id, name: id } } });

const notConfigured = () => ({
  success: false,
  error: {
    status: 503,
    message: 'compute is not configured',
    details: { reason: SERVICE_NOT_CONFIGURED },
  },
});

afterEach(() => {
  calls.get.length = 0;
  calls.metrics.length = 0;
});

describe('useContainerOps on a node without compute', () => {
  it('flags a structured not-configured GetContainer refusal as unavailable', async () => {
    const { result } = renderHook(() => useContainerOps('c1'));
    await act(async () => {
      settle(calls.get, 'c1', notConfigured());
    });

    expect(result.current.unavailable).toBe(true);
    expect(result.current.container).toBeNull();
    expect(result.current.loading).toBe(false);
  });

  it('a plain 503 without the reason is an error, not unavailable', async () => {
    const { result } = renderHook(() => useContainerOps('c1'));
    await act(async () => {
      settle(calls.get, 'c1', { success: false, error: { status: 503, message: 'busy' } });
    });

    expect(result.current.unavailable).toBe(false);
    expect(result.current.error).toBe('busy');
  });

  it('a later success clears unavailable', async () => {
    const { result } = renderHook(() => useContainerOps('c1'));
    await act(async () => {
      settle(calls.get, 'c1', notConfigured());
    });
    expect(result.current.unavailable).toBe(true);

    let pending: Promise<void> = Promise.resolve();
    act(() => {
      pending = result.current.refresh();
    });
    await act(async () => {
      settle(calls.get, 'c1', containerOf('c1'));
      await pending;
    });

    expect(result.current.unavailable).toBe(false);
    expect(result.current.container?.id).toBe('c1');
  });
});
