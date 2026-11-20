import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const service = {
  getTenantByName: vi.fn(),
  deleteTenant: vi.fn(),
  suspendTenant: vi.fn(),
  getTenant: vi.fn(),
};

vi.mock('trusted-platform-sdk', () => ({
  useTenant: () => service,
}));

import { useTenantLifecycle } from './use-tenant-lifecycle';

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void; reject: (e: Error) => void };

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  let reject!: (e: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function found(id: string, name: string) {
  return { success: true, data: { tenant: { id, name, state: 'TENANT_STATE_ACTIVE' } } };
}

/**
 * Overlapping tenant lookups: only the latest one selects the tenant that
 * remove, suspend and rotateDEK act on (#2023 Codex round 2).
 */
describe('useTenantLifecycle lookup', () => {
  beforeEach(() => {
    for (const fn of Object.values(service)) fn.mockReset();
  });

  afterEach(() => {
    cleanup();
  });

  it('a superseded lookup that finishes last does not replace the latest selection', async () => {
    const a = deferred<unknown>();
    const b = deferred<unknown>();
    service.getTenantByName.mockImplementation((name: string) => (name === 'alpha' ? a.promise : b.promise));
    service.deleteTenant.mockResolvedValue({ success: true, data: {} });

    const { result } = renderHook(() => useTenantLifecycle());

    let first!: Promise<void>;
    let second!: Promise<void>;
    act(() => {
      first = result.current.lookup('alpha');
    });
    act(() => {
      second = result.current.lookup('bravo');
    });

    await act(async () => {
      b.resolve(found('t-b', 'bravo'));
      await second;
    });
    expect(result.current.tenant?.id).toBe('t-b');
    expect(result.current.busy).toBe(false);

    await act(async () => {
      a.resolve(found('t-a', 'alpha'));
      await first;
    });
    expect(result.current.tenant?.id).toBe('t-b');
    expect(result.current.busy).toBe(false);

    await act(() => result.current.remove());
    expect(service.deleteTenant).toHaveBeenCalledWith('t-b');
    expect(result.current.notice).toBe('Tenant bravo deleted');
  });

  it('a superseded lookup that fails does not report its error or end the latest busy state', async () => {
    const a = deferred<unknown>();
    const b = deferred<unknown>();
    service.getTenantByName.mockImplementation((name: string) => (name === 'alpha' ? a.promise : b.promise));
    service.suspendTenant.mockResolvedValue({ success: true, data: {} });
    service.getTenant.mockResolvedValue(found('t-b', 'bravo'));

    const { result } = renderHook(() => useTenantLifecycle());

    let first!: Promise<void>;
    let second!: Promise<void>;
    act(() => {
      first = result.current.lookup('alpha');
    });
    act(() => {
      second = result.current.lookup('bravo');
    });

    await act(async () => {
      a.reject(new Error('alpha not found'));
      await first;
    });
    expect(result.current.error).toBeNull();
    expect(result.current.busy).toBe(true);

    await act(async () => {
      b.resolve(found('t-b', 'bravo'));
      await second;
    });
    expect(result.current.tenant?.id).toBe('t-b');
    expect(result.current.busy).toBe(false);

    await act(() => result.current.suspend());
    expect(service.suspendTenant).toHaveBeenCalledWith('t-b');
  });
});
