/**
 * Unit tests for the useMutation hook.
 *
 * The package carries no React renderer (no react-dom, no testing
 * library), so the React hook primitives the hook uses are replaced by a
 * small single-component runtime: state setters schedule a re-render on
 * the microtask queue, effects run after each render when their deps
 * change, and unmount runs every effect cleanup.
 */

import { describe, it, expect, vi } from 'vitest';
import type { ApiResponse } from '../../types/api.js';
import { ApiError } from '../../errors/api-error.js';
import { useMutation } from './use-mutation.js';
import type { MutationError, UseMutationOptions } from './use-mutation.js';

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

  const depsEqual = (a: readonly unknown[] | undefined, b: readonly unknown[] | undefined): boolean =>
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

    constructor(private readonly body: () => void) {}

    render(): void {
      this.index = 0;
      this.queued = [];
      active = this;
      try {
        this.body();
      } finally {
        active = undefined;
      }
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

  let active: Instance | undefined;
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
    useEffect(fn: () => void | (() => void), deps?: readonly unknown[]): void {
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
          slot.cleanup = typeof cleanup === 'function' ? cleanup : undefined;
        });
      }
    },
  };

  function renderHook<P, R>(
    hook: (props: P) => R,
    initialProps: P
  ): { result: { current: R }; rerender: (props: P) => void; unmount: () => void } {
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

type Fn<TData, TVars> = (vars: TVars) => Promise<ApiResponse<TData>>;

/** Render useMutation with a fixed function and options. */
function setup<TData, TVars>(fn: Fn<TData, TVars>, options?: UseMutationOptions<TData, TVars>) {
  return renderHook(() => useMutation(fn, options), undefined);
}

/** Run mutateAsync and return the rejection it must produce. */
async function rejection(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (err) {
    return err;
  }
  throw new Error('expected the mutation to reject');
}

describe('useMutation', () => {
  it('starts idle with nothing set', () => {
    const { result } = setup(() => Promise.resolve(ok(1)));
    expect(result.current.isIdle).toBe(true);
    expect(result.current.isLoading).toBe(false);
    expect(result.current.isSettled).toBe(false);
    expect(result.current.isError).toBe(false);
    expect(result.current.isSuccess).toBe(false);
    expect(result.current.data).toBeUndefined();
    expect(result.current.error).toBeUndefined();
    expect(result.current.variables).toBeUndefined();
  });

  it('keeps mutate, mutateAsync and reset stable across renders', async () => {
    const { result } = setup((n: number) => Promise.resolve(ok(n)));
    const { mutate, mutateAsync, reset } = result.current;
    await result.current.mutateAsync(1);
    await flush();
    expect(result.current.mutate).toBe(mutate);
    expect(result.current.mutateAsync).toBe(mutateAsync);
    expect(result.current.reset).toBe(reset);
  });

  describe('success', () => {
    it('is loading while pending, then resolves with the data', async () => {
      const d = deferred<ApiResponse<string>>();
      const fn = vi.fn((_: { id: number }) => d.promise);
      const { result } = setup(fn);

      const p = result.current.mutateAsync({ id: 3 });
      await flush();
      expect(fn).toHaveBeenCalledWith({ id: 3 });
      expect(result.current.isLoading).toBe(true);
      expect(result.current.isIdle).toBe(false);
      expect(result.current.variables).toEqual({ id: 3 });

      d.resolve(ok('done'));
      await expect(p).resolves.toBe('done');
      await flush();
      expect(result.current.data).toBe('done');
      expect(result.current.isSuccess).toBe(true);
      expect(result.current.isSettled).toBe(true);
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isError).toBe(false);
      expect(result.current.error).toBeUndefined();
    });

    it('calls onMutate, the function, onSuccess and onSettled in order', async () => {
      const order: string[] = [];
      const fn = vi.fn((v: string) => {
        order.push(`fn:${v}`);
        return Promise.resolve(ok(v.length));
      });
      const onMutate = vi.fn((v: string) => order.push(`onMutate:${v}`));
      const onSuccess = vi.fn((d: number, v: string) => order.push(`onSuccess:${d}:${v}`));
      const onSettled = vi.fn((d: number | undefined, e: MutationError | undefined, v: string) =>
        order.push(`onSettled:${String(d)}:${String(e)}:${v}`)
      );
      const onError = vi.fn();
      const { result } = setup(fn, { onMutate, onSuccess, onSettled, onError });

      await result.current.mutateAsync('abc');
      expect(order).toEqual(['onMutate:abc', 'fn:abc', 'onSuccess:3:abc', 'onSettled:3:undefined:abc']);
      expect(onError).not.toHaveBeenCalled();
    });

    it('treats falsy data other than undefined as a success', async () => {
      const { result } = setup(() => Promise.resolve(ok(false)));
      await expect(result.current.mutateAsync(undefined)).resolves.toBe(false);
      await flush();
      expect(result.current.isSuccess).toBe(true);
      expect(result.current.data).toBe(false);
    });
  });

  describe('error response', () => {
    it('maps the error body, keeping the status', async () => {
      const body = { code: 'CONFLICT', message: 'exists', status: 409 };
      const onError = vi.fn();
      const onSettled = vi.fn();
      const onSuccess = vi.fn();
      const { result } = setup((_: number) => Promise.resolve<ApiResponse<string>>({ error: body, success: false }), {
        onError,
        onSettled,
        onSuccess,
      });

      const err = await rejection(result.current.mutateAsync(5));
      const expected: MutationError = { code: 'CONFLICT', message: 'exists', status: 409, cause: body };
      expect(err).toEqual(expected);
      await flush();
      expect(result.current.error).toEqual(expected);
      expect(result.current.isError).toBe(true);
      expect(result.current.isSettled).toBe(true);
      expect(result.current.isSuccess).toBe(false);
      expect(result.current.data).toBeUndefined();
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith(expected, 5);
      expect(onSettled).toHaveBeenCalledWith(undefined, expected, 5);
      expect(onSuccess).not.toHaveBeenCalled();
    });

    it('leaves status out when the body has none', async () => {
      const { result } = setup(() =>
        Promise.resolve<ApiResponse<string>>({ error: { code: 'E', message: 'm' }, success: false })
      );
      const err = (await rejection(result.current.mutateAsync(undefined))) as MutationError;
      expect(err.code).toBe('E');
      expect('status' in err).toBe(false);
    });

    it('stringifies a non-string code and message', async () => {
      const body = { code: 500, message: 42 } as unknown as { code: string; message: string };
      const { result } = setup(() => Promise.resolve<ApiResponse<string>>({ error: body, success: false }));
      const err = (await rejection(result.current.mutateAsync(undefined))) as MutationError;
      expect(err.code).toBe('500');
      expect(err.message).toBe('42');
    });

    it('rejects an empty response with EMPTY_RESPONSE', async () => {
      const onError = vi.fn();
      const { result } = setup<string, number>(() => Promise.resolve({ success: true }), { onError });
      const err = await rejection(result.current.mutateAsync(1));
      const expected: MutationError = {
        code: 'EMPTY_RESPONSE',
        message: 'Mutation returned empty response',
      };
      expect(err).toEqual(expected);
      await flush();
      expect(result.current.error).toEqual(expected);
      expect(result.current.isError).toBe(true);
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith(expected, 1);
    });
  });

  describe('thrown errors', () => {
    it('maps a thrown Error to MUTATION_ERROR', async () => {
      const thrown = new Error('socket closed');
      const onError = vi.fn();
      const onSettled = vi.fn();
      const { result } = setup<string, number>(() => Promise.reject(thrown), { onError, onSettled });
      const err = await rejection(result.current.mutateAsync(2));
      const expected: MutationError = { code: 'MUTATION_ERROR', message: 'socket closed', cause: thrown };
      expect(err).toEqual(expected);
      await flush();
      expect(result.current.error).toEqual(expected);
      expect(result.current.isError).toBe(true);
      expect(onError).toHaveBeenCalledWith(expected, 2);
      expect(onSettled).toHaveBeenCalledWith(undefined, expected, 2);
    });

    it('maps an Error thrown synchronously by the function', async () => {
      const { result } = setup<string, undefined>(() => {
        throw new Error('sync');
      });
      const err = (await rejection(result.current.mutateAsync(undefined))) as MutationError;
      expect(err.code).toBe('MUTATION_ERROR');
      expect(err.message).toBe('sync');
    });

    it.each([
      ['a string', 'oops', 'oops'],
      ['a number', 7, '7'],
      ['null', null, 'null'],
      ['undefined', undefined, 'undefined'],
      ['an object without code', { reason: 'x' }, '[object Object]'],
    ])('maps %s to UNKNOWN_ERROR', async (_label, thrown, message) => {
      const { result } = setup<string, undefined>(() => Promise.reject(thrown));
      const err = await rejection(result.current.mutateAsync(undefined));
      expect(err).toEqual({ code: 'UNKNOWN_ERROR', message, cause: thrown });
      await flush();
      expect(result.current.isError).toBe(true);
    });

    it('maps a thrown ApiError, keeping code and status, and reports it', async () => {
      const thrown = new ApiError('unavailable', 'SERVICE_UNAVAILABLE', { status: 503 });
      const onError = vi.fn();
      const onSettled = vi.fn();
      const { result } = setup<string, number>(() => Promise.reject(thrown), { onError, onSettled });
      const err = await rejection(result.current.mutateAsync(4));
      const expected: MutationError = {
        code: 'SERVICE_UNAVAILABLE',
        message: 'unavailable',
        status: 503,
        cause: thrown,
      };
      expect(err).toEqual(expected);
      await flush();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.isError).toBe(true);
      expect(result.current.error).toEqual(expected);
      expect(onError).toHaveBeenCalledTimes(1);
      expect(onError).toHaveBeenCalledWith(expected, 4);
      expect(onSettled).toHaveBeenCalledWith(undefined, expected, 4);
    });

    it('maps a thrown plain object with code and message', async () => {
      const thrown = { code: 'X', message: 'plain' };
      const onError = vi.fn();
      const { result } = setup<string, undefined>(() => Promise.reject(thrown), { onError });
      await rejection(result.current.mutateAsync(undefined));
      await flush();
      expect(result.current.isError).toBe(true);
      expect(result.current.error).toEqual({ code: 'X', message: 'plain', cause: thrown });
      expect(onError).toHaveBeenCalledTimes(1);
    });
  });

  describe('mutate', () => {
    it('does not reject on error and reports through state and onError', async () => {
      const onError = vi.fn();
      const { result } = setup<string, number>(() => Promise.reject(new Error('nope')), { onError });
      expect(result.current.mutate(1)).toBeUndefined();
      await flush();
      expect(result.current.isError).toBe(true);
      expect(onError).toHaveBeenCalledTimes(1);
    });

    it('runs the mutation and stores the data', async () => {
      const onSuccess = vi.fn();
      const { result } = setup((n: number) => Promise.resolve(ok(n * 2)), { onSuccess });
      result.current.mutate(21);
      await flush();
      expect(result.current.data).toBe(42);
      expect(result.current.variables).toBe(21);
      expect(onSuccess).toHaveBeenCalledWith(42, 21);
    });
  });

  describe('reset', () => {
    it('returns to idle after a success', async () => {
      const { result } = setup((n: number) => Promise.resolve(ok(n)));
      await result.current.mutateAsync(1);
      await flush();
      result.current.reset();
      await flush();
      expect(result.current.isIdle).toBe(true);
      expect(result.current.data).toBeUndefined();
      expect(result.current.variables).toBeUndefined();
      expect(result.current.isSettled).toBe(false);
    });

    it('returns to idle after an error', async () => {
      const { result } = setup<string, number>(() => Promise.reject(new Error('x')));
      await rejection(result.current.mutateAsync(1));
      await flush();
      result.current.reset();
      await flush();
      expect(result.current.isIdle).toBe(true);
      expect(result.current.error).toBeUndefined();
      expect(result.current.isError).toBe(false);
    });
  });

  it('clears the previous error when a new mutation starts', async () => {
    let fail = true;
    const d = deferred<ApiResponse<number>>();
    const fn = (): Promise<ApiResponse<number>> => (fail ? Promise.reject(new Error('first')) : d.promise);
    const { result } = setup(fn);
    await rejection(result.current.mutateAsync(undefined));
    await flush();
    expect(result.current.isError).toBe(true);

    fail = false;
    const p = result.current.mutateAsync(undefined);
    await flush();
    expect(result.current.error).toBeUndefined();
    expect(result.current.isLoading).toBe(true);
    d.resolve(ok(1));
    await p;
  });

  it('uses the latest mutation function and options', async () => {
    const fnA = vi.fn((_: number) => Promise.resolve(ok('a')));
    const fnB = vi.fn((_: number) => Promise.resolve(ok('b')));
    const onA = vi.fn();
    const onB = vi.fn();
    const { result, rerender } = renderHook(
      (p: { fn: Fn<string, number>; onSuccess: (d: string) => void }) =>
        useMutation(p.fn, { onSuccess: p.onSuccess }),
      { fn: fnA, onSuccess: onA }
    );
    rerender({ fn: fnB, onSuccess: onB });
    await expect(result.current.mutateAsync(1)).resolves.toBe('b');
    expect(fnA).not.toHaveBeenCalled();
    expect(onA).not.toHaveBeenCalled();
    expect(onB).toHaveBeenCalledWith('b', 1);
  });

  describe('unmount', () => {
    it('rejects and skips callbacks when the response arrives after unmount', async () => {
      const d = deferred<ApiResponse<string>>();
      const onSuccess = vi.fn();
      const onError = vi.fn();
      const { result, unmount } = setup((_: number) => d.promise, { onSuccess, onError });
      const p = result.current.mutateAsync(1);
      unmount();
      d.resolve(ok('late'));
      const err = await rejection(p);
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).message).toBe('Component unmounted during mutation');
      expect(onSuccess).not.toHaveBeenCalled();
      expect(onError).not.toHaveBeenCalled();
    });

    it('rethrows the original rejection after unmount without callbacks', async () => {
      const d = deferred<ApiResponse<string>>();
      const onError = vi.fn();
      const { result, unmount } = setup((_: number) => d.promise, { onError });
      const p = result.current.mutateAsync(1);
      unmount();
      const thrown = new Error('late failure');
      d.reject(thrown);
      await expect(p).rejects.toBe(thrown);
      expect(onError).not.toHaveBeenCalled();
    });
  });
});
