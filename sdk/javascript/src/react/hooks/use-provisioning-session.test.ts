/**
<<<<<<< HEAD
 * Unit tests for the provisioning-session React hook (#1802).
 *
 * The hook runs as a plain function: the platform client context, useMutation
 * and useApi are mocked (see use-eab.test.ts for the rationale).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../context.js', () => ({ usePlatformClient: vi.fn() }));
vi.mock('./use-mutation.js', () => ({
  useMutation: vi.fn((fn: unknown) => ({ mutationFn: fn })),
}));
vi.mock('./use-api.js', () => ({ useApi: vi.fn() }));

import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import { useProvisioningSessions } from './use-provisioning-session.js';

type Fn = (...args: unknown[]) => Promise<unknown>;

const service = {
  listProvisioningSessions: vi.fn(),
  fulfillProvisioningSession: vi.fn(),
};

const refetch = vi.fn();

function listResult(data: unknown, extra: Record<string, unknown> = {}): void {
  vi.mocked(useApi).mockReturnValue({
    data,
    isLoading: false,
    error: null,
    refetch,
    ...extra,
  } as never);
}

function mutationFn(result: unknown): Fn {
  return (result as { mutationFn: Fn }).mutationFn;
}

function apiCall(): { fetcher: Fn; deps: unknown[]; options: unknown } {
  const calls = vi.mocked(useApi).mock.calls;
  const last = calls[calls.length - 1];
  if (!last) {
    throw new Error('useApi was not called');
  }
  return { fetcher: last[0] as Fn, deps: last[1], options: last[2] };
}

const s1 = { id: 's1', status: 'PENDING' };
const s2 = { id: 's2', status: 'FULFILLED' };

beforeEach(() => {
  vi.clearAllMocks();
  for (const fn of Object.values(service)) {
    fn.mockResolvedValue({ success: true, data: 'ok' });
  }
  refetch.mockResolvedValue(undefined);
  vi.mocked(usePlatformClient).mockReturnValue({ device: service } as never);
  listResult(undefined);
});

describe('useProvisioningSessions list fetcher', () => {
  it('lists sessions with no arguments, an empty dependency list and no options', async () => {
    useProvisioningSessions();
    const { fetcher, deps, options } = apiCall();
    expect(deps).toEqual([]);
    expect(options).toBeUndefined();
    await fetcher();
    expect(service.listProvisioningSessions).toHaveBeenCalledWith();
  });

  it('propagates a list rejection through the fetcher', async () => {
    service.listProvisioningSessions.mockRejectedValueOnce(new Error('list failed'));
    useProvisioningSessions();
    await expect(apiCall().fetcher()).rejects.toThrow('list failed');
  });
});

describe('useProvisioningSessions sessions', () => {
  it('returns a bare array response as is', () => {
    listResult([s1, s2]);
    expect(useProvisioningSessions().sessions).toEqual([s1, s2]);
  });

  it('unwraps a {sessions} envelope', () => {
    listResult({ sessions: [s2] });
    expect(useProvisioningSessions().sessions).toEqual([s2]);
  });

  it('returns an empty array for an empty envelope', () => {
    listResult({ sessions: [] });
    expect(useProvisioningSessions().sessions).toEqual([]);
  });

  it.each([
    ['undefined data', undefined],
    ['null data', null],
    ['an object without sessions', { total: 0 }],
    ['a non-array sessions field', { sessions: { id: 's1' } }],
    ['a string', 'sessions'],
    ['a boolean', true],
  ])('returns an empty list for %s', (_name, data) => {
    listResult(data);
    expect(useProvisioningSessions().sessions).toEqual([]);
  });
});

describe('useProvisioningSessions state', () => {
  it('passes isLoading through', () => {
    listResult(undefined, { isLoading: true });
    expect(useProvisioningSessions().isLoading).toBe(true);
  });

  it('passes an error through', () => {
    const err = new Error('boom');
    listResult(undefined, { error: err });
    expect(useProvisioningSessions().error).toBe(err);
  });

  it('maps an undefined error to null', () => {
    listResult(undefined, { error: undefined });
    expect(useProvisioningSessions().error).toBeNull();
  });

  it('refetch calls the list refetch and returns nothing', () => {
    const result = useProvisioningSessions();
    expect(result.refetch()).toBeUndefined();
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});

describe('useProvisioningSessions fulfill', () => {
  it('builds exactly one mutation', () => {
    useProvisioningSessions();
    expect(useMutation).toHaveBeenCalledTimes(1);
  });

  it('forwards the request to service.fulfillProvisioningSession', async () => {
    const req = { sessionId: 's1', profileId: 'p1' };
    await expect(mutationFn(useProvisioningSessions().fulfill)(req)).resolves.toEqual({
      success: true,
      data: 'ok',
    });
    expect(service.fulfillProvisioningSession).toHaveBeenCalledWith(req);
  });

  it('propagates a service rejection through the mutation function', async () => {
    service.fulfillProvisioningSession.mockRejectedValueOnce(new Error('session expired'));
    await expect(
      mutationFn(useProvisioningSessions().fulfill)({ sessionId: 'gone' })
    ).rejects.toThrow('session expired');
  });

  it('throws when the platform client is missing', () => {
    vi.mocked(usePlatformClient).mockImplementationOnce(() => {
      throw new Error('usePlatformClient must be used within a PlatformProvider');
    });
    expect(() => useProvisioningSessions()).toThrow('PlatformProvider');
=======
 * Unit tests for the useProvisioningSessions hook.
 *
 * The package carries no React renderer (no react-dom, no testing
 * library), so the React hook primitives the hook uses are replaced by a
 * small single-component runtime: state setters schedule a re-render on
 * the microtask queue, effects run after each render when their deps
 * change, and unmount runs every effect cleanup.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useProvisioningSessions } from './use-provisioning-session.js';
import type { UseProvisioningSessionsOptions } from './use-provisioning-session.js';

const runtime = vi.hoisted(() => {
  interface StateSlot {
    value: unknown;
    set: (next: unknown) => void;
  }
  interface EffectSlot {
    deps: readonly unknown[] | undefined;
    cleanup: (() => void) | undefined;
  }
  interface MemoSlot {
    value: unknown;
    deps: readonly unknown[];
  }

  const depsEqual = (
    a: readonly unknown[] | undefined,
    b: readonly unknown[] | undefined
  ): boolean =>
    a !== undefined &&
    b !== undefined &&
    a.length === b.length &&
    a.every((v, i) => Object.is(v, b[i]));

  class Instance {
    slots: unknown[] = [];
    index = 0;
    queued: Array<() => void> = [];
    scheduled = false;
    unmounted = false;
    renders = 0;

    constructor(private readonly body: () => void) {}

    render(): void {
      this.index = 0;
      this.queued = [];
      setActive(this);
      try {
        this.body();
      } finally {
        setActive(undefined);
      }
      this.renders += 1;
      const effects = this.queued;
      this.queued = [];
      for (const run of effects) {
        run();
      }
    }

    schedule(): void {
      if (this.scheduled || this.unmounted) {
        return;
      }
      this.scheduled = true;
      void Promise.resolve().then(() => {
        this.scheduled = false;
        if (!this.unmounted) {
          this.render();
        }
      });
    }

    unmount(): void {
      this.unmounted = true;
      for (const slot of this.slots) {
        const effect = slot as Partial<EffectSlot>;
        if (typeof effect === 'object' && effect !== null && 'cleanup' in effect) {
          effect.cleanup?.();
        }
      }
    }

    slot<S>(init: () => S): S {
      const i = this.index++;
      if (i >= this.slots.length) {
        this.slots.push(init());
      }
      return this.slots[i] as S;
    }
  }

  type EffectCallback = () => unknown;

  let active: Instance | undefined;
  function setActive(inst: Instance | undefined): void {
    active = inst;
  }
  const current = (): Instance => {
    if (active === undefined) {
      throw new Error('hook called outside a render');
    }
    return active;
  };

  const react = {
    useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void] {
      const inst = current();
      const slot = inst.slot<StateSlot>(() => {
        const s: StateSlot = {
          value: typeof initial === 'function' ? (initial as () => T)() : initial,
          set: (next: unknown) => {
            if (inst.unmounted) {
              return;
            }
            const value =
              typeof next === 'function' ? (next as (prev: unknown) => unknown)(s.value) : next;
            if (!Object.is(value, s.value)) {
              s.value = value;
              inst.schedule();
            }
          },
        };
        return s;
      });
      return [slot.value as T, slot.set as (next: T | ((prev: T) => T)) => void];
    },
    useRef<T>(initial: T): { current: T } {
      return current().slot(() => ({ current: initial }));
    },
    useCallback<F>(fn: F, deps: readonly unknown[]): F {
      const slot = current().slot<MemoSlot>(() => ({ value: fn, deps }));
      if (!depsEqual(slot.deps, deps)) {
        slot.value = fn;
        slot.deps = deps;
      }
      return slot.value as F;
    },
    useEffect(fn: EffectCallback, deps?: readonly unknown[]): void {
      const inst = current();
      let fresh = false;
      const slot = inst.slot<EffectSlot>(() => {
        fresh = true;
        return { deps, cleanup: undefined };
      });
      if (fresh || !depsEqual(slot.deps, deps)) {
        slot.deps = deps;
        inst.queued.push(() => {
          slot.cleanup?.();
          const cleanup = fn();
          slot.cleanup = typeof cleanup === 'function' ? (cleanup as () => void) : undefined;
        });
      }
    },
  };

  function renderHook<P, R>(
    hook: (props: P) => R,
    initialProps: P
  ): {
    result: { current: R };
    rerender: (props: P) => void;
    unmount: () => void;
    renders: () => number;
  } {
    let props = initialProps;
    const result = { current: undefined as unknown as R };
    const inst = new Instance(() => {
      result.current = hook(props);
    });
    inst.render();
    return {
      result,
      rerender: (next: P) => {
        props = next;
        inst.render();
      },
      unmount: () => inst.unmount(),
      renders: () => inst.renders,
    };
  }

  return { react, renderHook };
});

vi.mock('react', () => runtime.react);

const { renderHook } = runtime;

/** Let pending promises settle and scheduled re-renders run. */
async function flush(): Promise<void> {
  for (let i = 0; i < 20; i++) {
    await Promise.resolve();
  }
}

const client = vi.hoisted(() => ({
  device: {
    listProvisioningSessions: vi.fn(),
    fulfillProvisioningSession: vi.fn(),
  },
}));

vi.mock('../context.js', () => ({ usePlatformClient: () => client }));

const session = {
  id: 'sess-1',
  ek_serial: 'EK-1',
  mac_address: '02:00:00:00:00:01',
  fulfilled: false,
  created_at: '2026-11-01T00:00:00Z',
  expires_at: '2099-01-01T00:00:00Z',
};

beforeEach(() => {
  client.device.listProvisioningSessions.mockReset();
  client.device.fulfillProvisioningSession.mockReset();
});

describe('useProvisioningSessions', () => {
  it('lists a bare array answer', async () => {
    client.device.listProvisioningSessions.mockResolvedValue({ success: true, data: [session] });
    const { result } = renderHook(() => useProvisioningSessions(), undefined);
    await flush();
    expect(result.current.sessions).toEqual([session]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('lists a { sessions } answer', async () => {
    client.device.listProvisioningSessions.mockResolvedValue({
      success: true,
      data: { sessions: [session] },
    });
    const { result } = renderHook(() => useProvisioningSessions(), undefined);
    await flush();
    expect(result.current.sessions).toEqual([session]);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.error).toBeNull();
  });

  it('sends no list request while disabled', async () => {
    client.device.listProvisioningSessions.mockResolvedValue({ success: true, data: [session] });
    const { result } = renderHook(() => useProvisioningSessions({ enabled: false }), undefined);
    await flush();
    expect(client.device.listProvisioningSessions).not.toHaveBeenCalled();
    expect(result.current.sessions).toEqual([]);
    expect(result.current.isLoading).toBe(false);
    result.current.refetch();
    await flush();
    expect(client.device.listProvisioningSessions).not.toHaveBeenCalled();
  });

  it('lists once enabled turns true', async () => {
    client.device.listProvisioningSessions.mockResolvedValue({ success: true, data: [session] });
    const { result, rerender } = renderHook(
      (p: UseProvisioningSessionsOptions) => useProvisioningSessions(p),
      { enabled: false }
    );
    await flush();
    expect(client.device.listProvisioningSessions).not.toHaveBeenCalled();
    rerender({ enabled: true });
    await flush();
    expect(client.device.listProvisioningSessions).toHaveBeenCalledTimes(1);
    expect(result.current.sessions).toEqual([session]);
  });

  it('fulfils through the SDK', async () => {
    client.device.listProvisioningSessions.mockResolvedValue({ success: true, data: [] });
    // useMutation reports a success answer with undefined data as EMPTY_RESPONSE.
    client.device.fulfillProvisioningSession.mockResolvedValue({ success: true, data: null });
    const { result } = renderHook(() => useProvisioningSessions(), undefined);
    await flush();
    await result.current.fulfill.mutateAsync({ session_id: 'sess-1', profile_id: '7' });
    expect(client.device.fulfillProvisioningSession).toHaveBeenCalledWith({
      session_id: 'sess-1',
      profile_id: '7',
    });
>>>>>>> origin/main
  });
});
