/**
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
  });
});
