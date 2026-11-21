import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const platform = {
  getStatus: vi.fn(),
  getVersion: vi.fn(),
  getConfig: vi.fn(),
  listServices: vi.fn(),
  startService: vi.fn(),
  stopService: vi.fn(),
  restartService: vi.fn(),
  reloadConfig: vi.fn(),
  getServiceStatus: vi.fn(),
};

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  usePlatform: () => platform,
}));

import { usePlatformDaemon } from './use-platform-daemon';

type Deferred<T> = { promise: Promise<T>; resolve: (v: T) => void };

function deferred<T>(): Deferred<T> {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

function ok<T>(data: T) {
  return { success: true, data };
}

function failed(message: string) {
  return { success: false, error: { code: 'INTERNAL', message } };
}

function list(...names: string[]) {
  return ok({ services: names.map((name) => ({ name })) });
}

/** Service lifecycle actions of the platform daemon hook (#2023 Codex round 2). */
describe('usePlatformDaemon', () => {
  beforeEach(() => {
    for (const fn of Object.values(platform)) fn.mockReset();
    platform.getStatus.mockResolvedValue(ok({}));
    platform.getVersion.mockResolvedValue(ok({}));
    platform.getConfig.mockResolvedValue(ok({}));
    platform.listServices.mockResolvedValue(list('gatewayd'));
  });

  afterEach(() => {
    cleanup();
  });

  it.each([
    ['start', 'startService'],
    ['stop', 'stopService'],
    ['restart', 'restartService'],
  ] as const)('a successful %s refreshes the service list', async (action, method) => {
    platform[method].mockResolvedValue(ok({ success: true }));
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() => expect(result.current.services.data).toBeDefined());
    const before = platform.listServices.mock.calls.length;

    await act(async () => {
      await result.current.serviceAction('gatewayd', action);
    });

    expect(platform[method]).toHaveBeenCalledWith('gatewayd');
    expect(platform.listServices.mock.calls.length).toBe(before + 1);
    expect(result.current.isPending(`${action}:gatewayd`)).toBe(false);
  });

  it('a failed restart still refreshes the list and surfaces the error', async () => {
    platform.restartService.mockResolvedValue(failed('restart failed: unit did not start'));
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() => expect(result.current.services.data).toBeDefined());
    const before = platform.listServices.mock.calls.length;

    let caught: unknown;
    await act(async () => {
      try {
        await result.current.serviceAction('gatewayd', 'restart');
      } catch (err) {
        caught = err;
      }
    });

    expect((caught as Error).message).toBe('restart failed: unit did not start');
    expect(platform.listServices.mock.calls.length).toBe(before + 1);
    expect(result.current.lifecyclePending).toBe(false);
  });

  it('an SDK error response is rejected', async () => {
    platform.getServiceStatus.mockResolvedValue(failed('no such service'));
    const { result } = renderHook(() => usePlatformDaemon());

    await act(async () => {
      await expect(result.current.getServiceStatus('missing')).rejects.toThrow('no such service');
    });
    expect(result.current.isPending('status:missing')).toBe(false);
  });

  it('a stale pre-action list response does not overwrite the post-action list', async () => {
    const pre = deferred<unknown>();
    const post = deferred<unknown>();
    platform.listServices.mockReturnValueOnce(pre.promise).mockReturnValueOnce(post.promise);
    platform.stopService.mockResolvedValue(ok({ success: true }));
    const { result } = renderHook(() => usePlatformDaemon());
    await waitFor(() => expect(platform.listServices).toHaveBeenCalledTimes(1));

    await act(async () => {
      await result.current.serviceAction('gatewayd', 'stop');
    });
    expect(platform.listServices).toHaveBeenCalledTimes(2);

    await act(async () => {
      post.resolve(list('after-stop'));
      await post.promise;
    });
    await waitFor(() => expect(result.current.services.data).toEqual({ services: [{ name: 'after-stop' }] }));

    await act(async () => {
      pre.resolve(list('before-stop'));
      await pre.promise;
    });
    expect(result.current.services.data).toEqual({ services: [{ name: 'after-stop' }] });
  });

  it('overlapping requests keep the pending state until both settle', async () => {
    const first = deferred<unknown>();
    const second = deferred<unknown>();
    platform.startService.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const { result } = renderHook(() => usePlatformDaemon());

    let a!: Promise<unknown>;
    let b!: Promise<unknown>;
    act(() => {
      a = result.current.serviceAction('gatewayd', 'start');
      b = result.current.serviceAction('gatewayd', 'start');
    });
    expect(result.current.isPending('start:gatewayd')).toBe(true);
    expect(result.current.lifecyclePending).toBe(true);

    await act(async () => {
      first.resolve(ok({ success: true }));
      await a;
    });
    expect(result.current.isPending('start:gatewayd')).toBe(true);
    expect(result.current.lifecyclePending).toBe(true);

    await act(async () => {
      second.resolve(ok({ success: true }));
      await b;
    });
    expect(result.current.isPending('start:gatewayd')).toBe(false);
    expect(result.current.lifecyclePending).toBe(false);
  });
});
