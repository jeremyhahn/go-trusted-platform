/**
 * Unit tests for the useApi hook.
 *
 * The package carries no React renderer (no react-dom, no testing
 * library), so the React hook primitives the hook uses are replaced by a
 * small single-component runtime: state setters schedule a re-render on
 * the microtask queue, effects run after each render when their deps
 * change, and unmount runs every effect cleanup.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ApiResponse } from '../../types/api.js';
import { ApiError } from '../../errors/api-error.js';
import { useApi } from './use-api.js';

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

/** A promise with its resolve and reject handles exposed. */
function deferred<T>(): {
  promise: Promise<T>;
  resolve: (v: T) => void;
  reject: (e: unknown) => void;
} {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const ok = <T>(data: T): ApiResponse<T> => ({ data, success: true });

describe('useApi', () => {
  describe('initial fetch', () => {
    it('starts loading, then exposes the fetched data', async () => {
      const d = deferred<ApiResponse<number>>();
      const fetcher = vi.fn(() => d.promise);
      const { result } = renderHook(() => useApi(fetcher, []), undefined);

      expect(result.current.data).toBeUndefined();
      expect(result.current.isLoading).toBe(true);
      expect(result.current.isSuccess).toBe(false);
      await flush();
      expect(result.current.isFetching).toBe(true);
      expect(fetcher).toHaveBeenCalledTimes(1);

      d.resolve(ok(42));
      await flush();
      expect(result.current.data).toBe(42);
      expect(result.current.error).toBeUndefined();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isFetching).toBe(false);
      expect(result.current.isError).toBe(false);
      expect(result.current.isSuccess).toBe(true);
    });

    it('calls onSuccess with the data', async () => {
      const onSuccess = vi.fn();
      renderHook(() => useApi(() => Promise.resolve(ok('x')), [], { onSuccess }), undefined);
      await flush();
      expect(onSuccess).toHaveBeenCalledTimes(1);
      expect(onSuccess).toHaveBeenCalledWith('x');
    });

    it('treats falsy data other than undefined as a success', async () => {
      const { result } = renderHook(() => useApi(() => Promise.resolve(ok(0)), []), undefined);
      await flush();
      expect(result.current.data).toBe(0);
      expect(result.current.isSuccess).toBe(true);
    });

    it('settles a response that carries neither data nor error', async () => {
      const onSuccess = vi.fn();
      const onError = vi.fn();
      const { result } = renderHook(
        () => useApi<string>(() => Promise.resolve({ success: true }), [], { onSuccess, onError }),
        undefined
      );
      await flush();
      expect(result.current.data).toBeUndefined();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isFetching).toBe(false);
      expect(result.current.isError).toBe(false);
      expect(onSuccess).not.toHaveBeenCalled();
      expect(onError).not.toHaveBeenCalled();
    });
  });

  describe('errors', () => {
    it('exposes an error response and calls onError', async () => {
      const onError = vi.fn();
      const onSuccess = vi.fn();
      const errBody = { code: 'NOT_FOUND', message: 'missing', status: 404 };
      const { result } = renderHook(
        () =>
          useApi<number>(() => Promise.resolve({ error: errBody, success: false }), [], {
            onError,
            onSuccess,
          }),
        undefined
      );
      await flush();
      expect(result.current.error).toBe(errBody);
      expect(result.current.isError).toBe(true);
      expect(result.current.isSuccess).toBe(false);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isFetching).toBe(false);
      expect(result.current.data).toBeUndefined();
      expect(onError).toHaveBeenCalledWith(errBody);
      expect(onSuccess).not.toHaveBeenCalled();
    });

    it('exposes a rejected fetcher as the error', async () => {
      const onError = vi.fn();
      const thrown = new ApiError('network down', 'NETWORK_ERROR');
      const { result } = renderHook(
        () => useApi<number>(() => Promise.reject(thrown), [], { onError }),
        undefined
      );
      await flush();
      expect(result.current.error).toBe(thrown);
      expect(result.current.isError).toBe(true);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isFetching).toBe(false);
      expect(onError).toHaveBeenCalledWith(thrown);
    });

    it('keeps the last data but drops isSuccess when a refetch fails', async () => {
      let fail = false;
      const errBody = { code: 'E', message: 'boom' };
      const fetcher = (): Promise<ApiResponse<number>> =>
        Promise.resolve(fail ? { error: errBody, success: false } : ok(1));
      const { result } = renderHook(() => useApi(fetcher, []), undefined);
      await flush();
      expect(result.current.isSuccess).toBe(true);

      fail = true;
      await result.current.refetch();
      await flush();
      expect(result.current.data).toBe(1);
      expect(result.current.error).toBe(errBody);
      expect(result.current.isSuccess).toBe(false);
    });

    it('clears the error when a refetch succeeds', async () => {
      let fail = true;
      const fetcher = (): Promise<ApiResponse<number>> =>
        Promise.resolve(fail ? { error: { code: 'E', message: 'boom' }, success: false } : ok(7));
      const { result } = renderHook(() => useApi(fetcher, []), undefined);
      await flush();
      expect(result.current.isError).toBe(true);

      fail = false;
      await result.current.refetch();
      await flush();
      expect(result.current.error).toBeUndefined();
      expect(result.current.data).toBe(7);
      expect(result.current.isSuccess).toBe(true);
    });
  });

  describe('enabled', () => {
    it('does not fetch while disabled and is not loading', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      const { result } = renderHook(() => useApi(fetcher, [], { enabled: false }), undefined);
      await flush();
      expect(fetcher).not.toHaveBeenCalled();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isFetching).toBe(false);
    });

    it('refetch is a no-op while disabled', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      const { result } = renderHook(() => useApi(fetcher, [], { enabled: false }), undefined);
      await result.current.refetch();
      await flush();
      expect(fetcher).not.toHaveBeenCalled();
    });

    it('fetches once enabled flips to true', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok('on')));
      const { result, rerender } = renderHook(
        (enabled: boolean) => useApi(fetcher, [], { enabled }),
        false as boolean
      );
      await flush();
      expect(fetcher).not.toHaveBeenCalled();

      rerender(true);
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(result.current.data).toBe('on');
    });
  });

  describe('initialData', () => {
    it('serves initialData without a loading state and replaces it after the fetch', async () => {
      const d = deferred<ApiResponse<string>>();
      const { result } = renderHook(
        () => useApi(() => d.promise, [], { initialData: 'seed' }),
        undefined
      );
      expect(result.current.data).toBe('seed');
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isSuccess).toBe(false);

      d.resolve(ok('fresh'));
      await flush();
      expect(result.current.data).toBe('fresh');
      expect(result.current.isSuccess).toBe(true);
    });

    it('keeps initialData when disabled', async () => {
      const { result } = renderHook(
        () => useApi(() => Promise.resolve(ok('x')), [], { enabled: false, initialData: 'seed' }),
        undefined
      );
      await flush();
      expect(result.current.data).toBe('seed');
      expect(result.current.isLoading).toBe(false);
    });
  });

  describe('deps', () => {
    it('refetches when a dep changes and not when it stays the same', async () => {
      const fetcher = vi.fn((id: string) => Promise.resolve(ok(`item-${id}`)));
      const { result, rerender } = renderHook(
        (id: string) => useApi(() => fetcher(id), [id]),
        'a' as string
      );
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(result.current.data).toBe('item-a');

      rerender('a');
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(1);

      rerender('b');
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(fetcher).toHaveBeenLastCalledWith('b');
      expect(result.current.data).toBe('item-b');
    });

    it('refetches when the deps array changes length', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      const { rerender } = renderHook((deps: unknown[]) => useApi(fetcher, deps), [1]);
      await flush();
      rerender([1, 2]);
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(2);
    });

    it('does not show isLoading again on a refetch after the first success', async () => {
      const d = deferred<ApiResponse<number>>();
      let call = 0;
      const fetcher = (): Promise<ApiResponse<number>> =>
        ++call === 1 ? Promise.resolve(ok(1)) : d.promise;
      const { result } = renderHook(() => useApi(fetcher, []), undefined);
      await flush();

      void result.current.refetch();
      await flush();
      expect(result.current.isFetching).toBe(true);
      expect(result.current.isLoading).toBe(false);
      d.resolve(ok(2));
      await flush();
      expect(result.current.data).toBe(2);
    });
  });

  describe('refetch', () => {
    it('calls the latest fetcher', async () => {
      const first = vi.fn(() => Promise.resolve(ok('first')));
      const second = vi.fn(() => Promise.resolve(ok('second')));
      const { result, rerender } = renderHook(
        (f: () => Promise<ApiResponse<string>>) => useApi(f, []),
        first
      );
      await flush();
      rerender(second);
      await result.current.refetch();
      await flush();
      expect(first).toHaveBeenCalledTimes(1);
      expect(second).toHaveBeenCalledTimes(1);
      expect(result.current.data).toBe('second');
    });

    it('uses the latest onSuccess callback', async () => {
      const a = vi.fn();
      const b = vi.fn();
      const { result, rerender } = renderHook(
        (cb: (n: number) => void) => useApi(() => Promise.resolve(ok(1)), [], { onSuccess: cb }),
        a
      );
      await flush();
      rerender(b);
      await result.current.refetch();
      await flush();
      expect(a).toHaveBeenCalledTimes(1);
      expect(b).toHaveBeenCalledTimes(1);
    });
  });

  describe('mutate', () => {
    it('replaces data with a value', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok([1])));
      const { result } = renderHook(() => useApi(fetcher, []), undefined);
      await flush();
      result.current.mutate([9]);
      await flush();
      expect(result.current.data).toEqual([9]);
      expect(fetcher).toHaveBeenCalledTimes(1);
    });

    it('updates data with a function of the previous value', async () => {
      const { result } = renderHook(() => useApi(() => Promise.resolve(ok([1])), []), undefined);
      await flush();
      result.current.mutate((prev) => [...(prev ?? []), 2]);
      await flush();
      expect(result.current.data).toEqual([1, 2]);
    });

    it('passes undefined to the updater before any data exists', async () => {
      const updater = vi.fn((prev: number | undefined) => (prev ?? 0) + 1);
      const { result } = renderHook(
        () => useApi<number>(() => Promise.resolve(ok(5)), [], { enabled: false }),
        undefined
      );
      result.current.mutate(updater);
      await flush();
      expect(updater).toHaveBeenCalledWith(undefined);
      expect(result.current.data).toBe(1);
    });

    it('keeps the same function identity across renders', async () => {
      const { result } = renderHook(() => useApi(() => Promise.resolve(ok(1)), []), undefined);
      const first = result.current.mutate;
      await flush();
      expect(result.current.mutate).toBe(first);
    });
  });

  describe('unmount', () => {
    it('ignores a response that arrives after unmount', async () => {
      const d = deferred<ApiResponse<number>>();
      const onSuccess = vi.fn();
      const { result, unmount, renders } = renderHook(
        () => useApi(() => d.promise, [], { onSuccess }),
        undefined
      );
      await flush();
      unmount();
      const before = renders();
      d.resolve(ok(1));
      await flush();
      expect(onSuccess).not.toHaveBeenCalled();
      expect(result.current.data).toBeUndefined();
      expect(renders()).toBe(before);
    });

    it('ignores a rejection that arrives after unmount', async () => {
      const d = deferred<ApiResponse<number>>();
      const onError = vi.fn();
      const { unmount } = renderHook(() => useApi(() => d.promise, [], { onError }), undefined);
      await flush();
      unmount();
      d.reject(new Error('late'));
      await flush();
      expect(onError).not.toHaveBeenCalled();
    });
  });

  describe('refetchInterval', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('polls at the interval', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      renderHook(() => useApi(fetcher, [], { refetchInterval: 1000 }), undefined);
      await flush();
      expect(fetcher).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(1000);
      expect(fetcher).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(2000);
      expect(fetcher).toHaveBeenCalledTimes(4);
    });

    it.each([0, -1])('does not poll for interval %d', async (interval) => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      renderHook(() => useApi(fetcher, [], { refetchInterval: interval }), undefined);
      await flush();
      await vi.advanceTimersByTimeAsync(10_000);
      expect(fetcher).toHaveBeenCalledTimes(1);
    });

    it('does not poll while disabled', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      renderHook(() => useApi(fetcher, [], { refetchInterval: 100, enabled: false }), undefined);
      await vi.advanceTimersByTimeAsync(1000);
      expect(fetcher).not.toHaveBeenCalled();
    });

    it('stops polling on unmount', async () => {
      const fetcher = vi.fn(() => Promise.resolve(ok(1)));
      const { unmount } = renderHook(
        () => useApi(fetcher, [], { refetchInterval: 100 }),
        undefined
      );
      await flush();
      unmount();
      await vi.advanceTimersByTimeAsync(1000);
      expect(fetcher).toHaveBeenCalledTimes(1);
    });
  });
});
