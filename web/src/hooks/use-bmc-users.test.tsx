import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useBMCUsers, type BMCUserSlot } from './use-bmc-users';

interface Pending {
  method: string;
  url: string;
  resolve: (payload: unknown) => void;
}

// Every fetch stays pending until the test answers it, so a test controls
// the order in which two profiles' listings settle.
let pending: Pending[] = [];

function answer(url: string, payload: unknown): void {
  const i = pending.findIndex((p) => p.url === url);
  if (i < 0) throw new Error(`no pending request for ${url}`);
  const [p] = pending.splice(i, 1);
  p.resolve(payload);
}

const alice: BMCUserSlot = { slot: 3, username: 'alice', enabled: true, privilege: 4, channel: 1 };
const bob: BMCUserSlot = { slot: 3, username: 'bob', enabled: true, privilege: 2, channel: 1 };

beforeEach(() => {
  pending = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(
      (url: string, init?: RequestInit) =>
        new Promise((resolve) => {
          pending.push({
            method: init?.method ?? 'GET',
            url,
            resolve: (payload) =>
              resolve({
                ok: true,
                status: 200,
                text: async () => JSON.stringify({ payload }),
              }),
          });
        })
    )
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const flush = () => act(async () => {});

describe('useBMCUsers across a profile change', () => {
  it("drops the previous profile's rows and refuses slot mutations until the new profile lists", async () => {
    const { result, rerender } = renderHook(({ id }) => useBMCUsers(id), {
      initialProps: { id: '7' },
    });
    await flush();
    await act(async () => answer('/api/v1/bmc/7/users', [alice]));
    await waitFor(() => expect(result.current.listed).toBe(true));
    expect(result.current.users).toEqual([alice]);

    rerender({ id: '9' });
    // Profile 9 has not listed: profile 7's alice must not be actionable.
    expect(result.current.users).toEqual([]);
    expect(result.current.listed).toBe(false);
    expect(result.current.isLoading).toBe(true);

    await expect(result.current.deleteUser(3)).rejects.toThrow();
    await expect(result.current.setUserPassword(3, 'pw')).rejects.toThrow();
    await expect(result.current.setUserPrivilege(3, 'user', 1)).rejects.toThrow();
    expect(pending.filter((p) => p.method !== 'GET')).toEqual([]);
  });

  it("discards a superseded listing that settles after the newer profile's", async () => {
    const { result, rerender } = renderHook(({ id }) => useBMCUsers(id), {
      initialProps: { id: '7' },
    });
    await flush();
    rerender({ id: '9' });
    await flush();
    expect(pending.map((p) => p.url).sort()).toEqual([
      '/api/v1/bmc/7/users',
      '/api/v1/bmc/9/users',
    ]);

    await act(async () => answer('/api/v1/bmc/9/users', [bob]));
    await waitFor(() => expect(result.current.listed).toBe(true));
    // Profile 7's delayed listing settles last; it must not replace bob.
    await act(async () => answer('/api/v1/bmc/7/users', [alice]));
    await flush();
    expect(result.current.users).toEqual([bob]);
    expect(result.current.listed).toBe(true);
  });

  // A mutation started on profile 7 settles after the hook moved to
  // profile 9 and 9 has listed: its follow-up listing must not run for 7,
  // and 9's rows must stay listed.
  const mutations: Array<{
    name: string;
    method: string;
    url: string;
    run: (r: ReturnType<typeof useBMCUsers>) => Promise<void>;
  }> = [
    { name: 'deleteUser', method: 'DELETE', url: '/api/v1/bmc/7/users/3', run: (r) => r.deleteUser(3) },
    {
      name: 'createUser',
      method: 'POST',
      url: '/api/v1/bmc/7/users',
      run: (r) =>
        r.createUser({ slot: 4, username: 'carol', password: 'pw', privilege: 'user', enabled: true, channel: 1 }),
    },
    {
      name: 'setUserPrivilege',
      method: 'PUT',
      url: '/api/v1/bmc/7/users/3/privilege',
      run: (r) => r.setUserPrivilege(3, 'operator', 1),
    },
  ];

  it.each(mutations)(
    "keeps the new profile's rows when a $name of the previous profile settles last",
    async ({ method, url, run }) => {
      const { result, rerender } = renderHook(({ id }) => useBMCUsers(id), {
        initialProps: { id: '7' },
      });
      await flush();
      await act(async () => answer('/api/v1/bmc/7/users', [alice]));
      await waitFor(() => expect(result.current.listed).toBe(true));

      let done: Promise<void> = Promise.resolve();
      await act(async () => {
        done = run(result.current);
      });
      expect(pending.some((p) => p.method === method && p.url === url)).toBe(true);

      rerender({ id: '9' });
      await flush();
      await act(async () => answer('/api/v1/bmc/9/users', [bob]));
      await waitFor(() => expect(result.current.listed).toBe(true));

      await act(async () => answerMethod(method, url, {}));
      await flush();
      await flush();

      // A follow-up listing of profile 7 must not have started. Answer any
      // that did, so the mutation settles and the test can check the rows.
      const stale = pending.filter((p) => p.url.startsWith('/api/v1/bmc/7/')).map((p) => p.url);
      await act(async () => {
        for (const u of stale) answer(u, [alice]);
        await done;
      });
      await flush();

      expect(stale).toEqual([]);
      expect(result.current.users).toEqual([bob]);
      expect(result.current.listed).toBe(true);
      expect(result.current.isLoading).toBe(false);
    }
  );
});

function answerMethod(method: string, url: string, payload: unknown): void {
  const i = pending.findIndex((p) => p.method === method && p.url === url);
  if (i < 0) throw new Error(`no pending ${method} ${url}`);
  const [p] = pending.splice(i, 1);
  p.resolve(payload);
}
