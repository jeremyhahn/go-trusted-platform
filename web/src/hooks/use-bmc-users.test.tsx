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
});
