import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

interface Deferred {
  key: string;
  resolve: (value: unknown) => void;
}

const calls = vi.hoisted(() => ({
  get: [] as Deferred[],
  getByToken: [] as Deferred[],
}));

const service = vi.hoisted(() => ({
  get: vi.fn(
    (id: string) =>
      new Promise((resolve) => {
        calls.get.push({ key: id, resolve });
      })
  ),
  getByToken: vi.fn(
    (token: string) =>
      new Promise((resolve) => {
        calls.getByToken.push({ key: token, resolve });
      })
  ),
}));

vi.mock('trusted-platform-sdk', async (importOriginal) => ({
  ...(await importOriginal<typeof import('trusted-platform-sdk')>()),
  useInvitation: () => ({ service }),
}));

import { useInvitationById, useInvitationByToken } from './use-invitation-detail';

function settle(list: Deferred[], key: string, value: unknown): void {
  const i = list.findIndex((d) => d.key === key);
  if (i < 0) throw new Error(`no pending request for ${key}`);
  const [d] = list.splice(i, 1);
  d.resolve(value);
}

const ok = (id: string) => ({
  success: true,
  data: { invitation: { id, email: `${id}@example.test` } },
});

afterEach(() => {
  calls.get.length = 0;
  calls.getByToken.length = 0;
  service.get.mockClear();
  service.getByToken.mockClear();
});

describe('useInvitationById across an id change', () => {
  it('shows nothing of A while B loads', async () => {
    const { result, rerender } = renderHook(({ id }) => useInvitationById(id), {
      initialProps: { id: 'inv-a' },
    });
    await act(async () => {
      settle(calls.get, 'inv-a', ok('inv-a'));
    });
    expect(result.current.data?.invitation.id).toBe('inv-a');

    rerender({ id: 'inv-b' });
    expect(result.current.data).toBeUndefined();
    expect(result.current.isLoading).toBe(true);
  });

  it("drops A's reply that settles after B's", async () => {
    const { result, rerender } = renderHook(({ id }) => useInvitationById(id), {
      initialProps: { id: 'inv-a' },
    });
    rerender({ id: 'inv-b' });

    await act(async () => {
      settle(calls.get, 'inv-b', ok('inv-b'));
    });
    await act(async () => {
      settle(calls.get, 'inv-a', ok('inv-a'));
    });

    expect(result.current.data?.invitation.id).toBe('inv-b');
    expect(result.current.isLoading).toBe(false);
  });

  it('an empty id loads nothing', () => {
    const { result } = renderHook(() => useInvitationById(''));
    expect(service.get).not.toHaveBeenCalled();
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toBeUndefined();
  });
});

describe('useInvitationByToken across a token change', () => {
  it("drops A's reply that settles after B's", async () => {
    const { result, rerender } = renderHook(({ token }) => useInvitationByToken(token), {
      initialProps: { token: 'tok-a' },
    });
    rerender({ token: 'tok-b' });

    await act(async () => {
      settle(calls.getByToken, 'tok-b', ok('tok-b'));
    });
    await act(async () => {
      settle(calls.getByToken, 'tok-a', ok('tok-a'));
    });

    expect(result.current.data?.invitation.id).toBe('tok-b');
  });
});
