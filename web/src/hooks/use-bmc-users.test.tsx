import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useBMCUsers, type BMCUserSlot, type CreateBMCUserInput } from './use-bmc-users';

// useBMCUsers drives PlatformClient.bmc (BMCService), never a direct fetch,
// so the SDK's base URL, auth interceptors and transport apply (#1675 F27).

const bmc = {
  listUsers: vi.fn(),
  createUser: vi.fn(),
  deleteUser: vi.fn(),
  setUserPassword: vi.fn(),
  setUserPrivilege: vi.fn(),
  replaceWebCertificate: vi.fn(),
};

// One stable client: a new object per render would re-run the hook's effects.
const client = { bmc };

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => client,
}));

interface Pending {
  id: string;
  resolve: (users: BMCUserSlot[]) => void;
}

// Every listing stays pending until the test answers it, so a test controls
// the order in which two profiles' listings settle.
let pending: Pending[] = [];

function answer(id: string, users: BMCUserSlot[]): void {
  const i = pending.findIndex((p) => p.id === id);
  if (i < 0) throw new Error(`no pending listing for profile ${id}`);
  const [p] = pending.splice(i, 1);
  p.resolve(users);
}

const alice: BMCUserSlot = { slot: 3, username: 'alice', enabled: true, privilege: 4, channel: 1 };
const bob: BMCUserSlot = { slot: 3, username: 'bob', enabled: true, privilege: 2, channel: 1 };

beforeEach(() => {
  pending = [];
  bmc.listUsers.mockImplementation(
    (id: string | number) =>
      new Promise((r) => {
        pending.push({ id: String(id), resolve: (users) => r({ success: true, data: users }) });
      })
  );
  for (const m of [bmc.createUser, bmc.deleteUser, bmc.setUserPassword, bmc.setUserPrivilege, bmc.replaceWebCertificate]) {
    m.mockResolvedValue({ success: true, data: { status: 'ok' } });
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('the BMC hooks must not call fetch');
    })
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

const flush = () => act(async () => {});

async function listedAs7(users: BMCUserSlot[]) {
  const hook = renderHook(({ id }) => useBMCUsers(id), { initialProps: { id: '7' } });
  await flush();
  await act(async () => answer('7', users));
  await waitFor(() => expect(hook.result.current.listed).toBe(true));
  return hook;
}

describe('useBMCUsers across a profile change', () => {
  it("drops the previous profile's rows and refuses slot mutations until the new profile lists", async () => {
    const { result, rerender } = await listedAs7([alice]);
    expect(result.current.users).toEqual([alice]);

    rerender({ id: '9' });
    // Profile 9 has not listed: profile 7's alice must not be actionable.
    expect(result.current.users).toEqual([]);
    expect(result.current.listed).toBe(false);
    expect(result.current.isLoading).toBe(true);

    await expect(result.current.deleteUser(3)).rejects.toThrow();
    await expect(result.current.setUserPassword(3, 'pw')).rejects.toThrow();
    await expect(result.current.setUserPrivilege(3, 'user', 1)).rejects.toThrow();
    expect(bmc.deleteUser).not.toHaveBeenCalled();
    expect(bmc.setUserPassword).not.toHaveBeenCalled();
    expect(bmc.setUserPrivilege).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("discards a superseded listing that settles after the newer profile's", async () => {
    const { result, rerender } = renderHook(({ id }) => useBMCUsers(id), {
      initialProps: { id: '7' },
    });
    await flush();
    rerender({ id: '9' });
    await flush();
    expect(pending.map((p) => p.id).sort()).toEqual(['7', '9']);

    await act(async () => answer('9', [bob]));
    await waitFor(() => expect(result.current.listed).toBe(true));
    // Profile 7's delayed listing settles last; it must not replace bob.
    await act(async () => answer('7', [alice]));
    await flush();
    expect(result.current.users).toEqual([bob]);
    expect(result.current.listed).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('useBMCUsers calls client.bmc', () => {
  it('createUser sends the input through client.bmc and lists again', async () => {
    const { result } = await listedAs7([alice]);
    const input: CreateBMCUserInput = {
      slot: 4,
      username: 'carol',
      password: 'pw',
      privilege: 'operator',
      enabled: true,
      channel: 1,
    };
    let done!: Promise<void>;
    act(() => {
      done = result.current.createUser(input);
    });
    await waitFor(() => expect(bmc.listUsers).toHaveBeenCalledTimes(2));
    expect(bmc.createUser).toHaveBeenCalledWith('7', input);
    expect(bmc.listUsers).toHaveBeenLastCalledWith('7');
    await act(async () => {
      answer('7', [alice]);
      await done;
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('deleteUser, setUserPassword, setUserPrivilege and replaceWebCertificate pass the profile ID', async () => {
    const { result } = await listedAs7([alice]);

    let done!: Promise<void>;
    act(() => {
      done = result.current.deleteUser(3);
    });
    await waitFor(() => expect(pending.length).toBe(1));
    await act(async () => {
      answer('7', [alice]);
      await done;
    });
    expect(bmc.deleteUser).toHaveBeenCalledWith('7', 3);

    await act(() => result.current.setUserPassword(3, 'pw'));
    expect(bmc.setUserPassword).toHaveBeenCalledWith('7', 3, 'pw');

    act(() => {
      done = result.current.setUserPrivilege(3, 'user', 1);
    });
    await waitFor(() => expect(pending.length).toBe(1));
    await act(async () => {
      answer('7', [alice]);
      await done;
    });
    expect(bmc.setUserPrivilege).toHaveBeenCalledWith('7', 3, 'user', 1);

    await act(() => result.current.replaceWebCertificate('C', 'K'));
    expect(bmc.replaceWebCertificate).toHaveBeenCalledWith('7', { certPem: 'C', keyPem: 'K' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('a failed listing is the SDK error message', async () => {
    bmc.listUsers.mockResolvedValue({
      success: false,
      error: { code: 'HTTP_502', message: 'ipmi: session refused', status: 502 },
    });
    const { result } = renderHook(() => useBMCUsers('7'));
    await waitFor(() => expect(result.current.error).toBe('ipmi: session refused'));
    expect(result.current.listed).toBe(false);
    expect(result.current.users).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
  });
});
