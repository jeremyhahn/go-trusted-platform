import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useBMCUsers, type BMCUserSlot } from './use-bmc-users';

interface Pending {
  method: string;
  url: string;
  resolve: (payload: unknown) => void;
}

// Every SDK call stays pending until the test answers it, so a test
// controls the order in which two profiles' listings settle. Each call is
// recorded with the REST method and path its BMCService method sends.
let pending: Pending[] = [];

function sdkCall(method: string, path: (id: string, ...rest: never[]) => string) {
  return vi.fn(
    (id: string, ...rest: never[]) =>
      new Promise((resolve) => {
        pending.push({
          method,
          url: `/api/v1/bmc/${encodeURIComponent(id)}${path(id, ...rest)}`,
          resolve: (payload) => resolve({ success: true, data: payload }),
        });
      })
  );
}

const bmc = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => ({ bmc }),
}));

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
  Object.assign(bmc, {
    listUsers: sdkCall('GET', () => '/users'),
    createUser: sdkCall('POST', () => '/users'),
    deleteUser: sdkCall('DELETE', (_id, slot: number) => `/users/${slot}`),
    setUserPassword: sdkCall('PUT', (_id, slot: number) => `/users/${slot}/password`),
    setUserPrivilege: sdkCall('PUT', (_id, slot: number) => `/users/${slot}/privilege`),
    replaceWebCertificate: sdkCall('PUT', () => '/cert'),
  });
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

// #2023 Codex round 5: a successful answer whose payload is not a user
// list (no payload, an empty body, an object) never established slot
// occupancy, so it must not mark the profile listed, and createUser must
// send nothing.
describe('useBMCUsers with an unreadable listing', () => {
  const unreadable = [
    { name: 'no payload', res: { success: true } },
    { name: 'an empty body', res: { success: true, data: '' } },
    { name: 'an object payload', res: { success: true, data: {} } },
    { name: 'a non-array payload', res: { success: true, data: { slot: 3 } } },
  ];

  it.each(unreadable)('keeps listed false and refuses createUser after $name', async ({ res }) => {
    bmc.listUsers = vi.fn(async () => res);
    const { result } = renderHook(() => useBMCUsers('7'));
    await flush();
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.listed).toBe(false);
    expect(result.current.error).toMatch(/unreadable user listing/);
    expect(result.current.users).toEqual([]);
    await expect(
      result.current.createUser({ slot: 3, username: 'eve', password: 'pw', privilege: 4, channel: 1 } as never)
    ).rejects.toThrow(/still loading|unreadable/);
    expect(bmc.createUser).not.toHaveBeenCalled();
    expect(pending).toEqual([]);
  });

  it('lists an empty array as listed with no users', async () => {
    bmc.listUsers = vi.fn(async () => ({ success: true, data: [] }));
    const { result } = renderHook(() => useBMCUsers('7'));
    await flush();
    await waitFor(() => expect(result.current.listed).toBe(true));
    expect(result.current.error).toBeNull();
    expect(result.current.users).toEqual([]);
  });
});
