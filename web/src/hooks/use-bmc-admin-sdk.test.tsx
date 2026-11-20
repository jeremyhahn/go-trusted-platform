/**
 * #2040: every BMC admin operation of the console goes through the SDK
 * BMCService (`usePlatformClient().bmc`), never a hand-written fetch.
 */
import { act, cleanup, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { useBMCCertOps } from './use-bmc-cert-ops';
import { useBMCUsers } from './use-bmc-users';

const bmc = vi.hoisted(() => ({
  enrollBMC: vi.fn(),
  restoreFactoryCert: vi.fn(),
  listUsers: vi.fn(),
  createUser: vi.fn(),
  deleteUser: vi.fn(),
  setUserPassword: vi.fn(),
  setUserPrivilege: vi.fn(),
  replaceWebCertificate: vi.fn(),
}));

vi.mock('trusted-platform-sdk', () => ({
  usePlatformClient: () => ({ bmc }),
}));

const ok = (data: unknown) => ({ success: true, data });
const refused = (message: string) => ({ success: false, error: { message } });

const alice = { slot: 3, username: 'alice', enabled: true, privilege: 4, channel: 1 };

beforeEach(() => {
  for (const fn of Object.values(bmc)) fn.mockReset();
  bmc.enrollBMC.mockResolvedValue(ok({ steps: [] }));
  bmc.restoreFactoryCert.mockResolvedValue(ok({ restored: true }));
  bmc.listUsers.mockResolvedValue(ok([alice]));
  for (const fn of [bmc.createUser, bmc.deleteUser, bmc.setUserPassword, bmc.setUserPrivilege, bmc.replaceWebCertificate]) {
    fn.mockResolvedValue(ok({}));
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(() => {
      throw new Error('BMC admin hooks must call the SDK client, not fetch');
    })
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('useBMCCertOps through the SDK BMCService', () => {
  it('enrols with the SDK request and restores the factory certificate', async () => {
    const { result } = renderHook(() => useBMCCertOps('7'));
    await act(async () => {
      await result.current.enroll({ replaceCertificate: true });
    });
    expect(bmc.enrollBMC).toHaveBeenCalledWith('7', { replaceCertificate: true });
    expect(result.current.error).toBeNull();
    expect(result.current.lastResult).toMatchObject({ operation: 'enroll', result: { steps: [] } });

    await act(async () => {
      await result.current.restoreFactoryCert();
    });
    expect(bmc.restoreFactoryCert).toHaveBeenCalledWith('7');
    expect(result.current.lastResult).toMatchObject({ operation: 'restore', result: { restored: true } });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('shows the server message of a refused call', async () => {
    bmc.restoreFactoryCert.mockResolvedValue(refused('missing scope bmc.cert'));
    const { result } = renderHook(() => useBMCCertOps('7'));
    let out: unknown = 'unset';
    await act(async () => {
      out = await result.current.restoreFactoryCert();
    });
    expect(out).toBeNull();
    expect(result.current.error).toBe('missing scope bmc.cert');
  });
});

describe('useBMCUsers through the SDK BMCService', () => {
  async function listedHook() {
    const hook = renderHook(() => useBMCUsers('7'));
    await waitFor(() => expect(hook.result.current.listed).toBe(true));
    expect(bmc.listUsers).toHaveBeenCalledWith('7');
    expect(hook.result.current.users).toEqual([alice]);
    bmc.listUsers.mockClear();
    return hook;
  }

  it('creates a user with the same body fields, then reloads', async () => {
    const { result } = await listedHook();
    const input = { slot: 4, username: 'carol', password: 'pw', privilege: 'user' as const, enabled: true, channel: 1 };
    await act(async () => {
      await result.current.createUser(input);
    });
    expect(bmc.createUser).toHaveBeenCalledWith('7', input);
    expect(bmc.listUsers).toHaveBeenCalledWith('7');
  });

  it('deletes a slot, then reloads', async () => {
    const { result } = await listedHook();
    await act(async () => {
      await result.current.deleteUser(3);
    });
    expect(bmc.deleteUser).toHaveBeenCalledWith('7', 3);
    expect(bmc.listUsers).toHaveBeenCalledWith('7');
  });

  it('sets a password', async () => {
    const { result } = await listedHook();
    await act(async () => {
      await result.current.setUserPassword(3, 's3cret');
    });
    expect(bmc.setUserPassword).toHaveBeenCalledWith('7', 3, 's3cret');
  });

  it('sets a privilege, then reloads', async () => {
    const { result } = await listedHook();
    await act(async () => {
      await result.current.setUserPrivilege(3, 'operator', 1);
    });
    expect(bmc.setUserPrivilege).toHaveBeenCalledWith('7', 3, 'operator', 1);
    expect(bmc.listUsers).toHaveBeenCalledWith('7');
  });

  it('replaces the web certificate', async () => {
    const { result } = await listedHook();
    await act(async () => {
      await result.current.replaceWebCertificate('CERT', 'KEY');
    });
    expect(bmc.replaceWebCertificate).toHaveBeenCalledWith('7', { certPem: 'CERT', keyPem: 'KEY' });
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects a refused mutation with the server message', async () => {
    const { result } = await listedHook();
    bmc.deleteUser.mockResolvedValue(refused('permission denied: bmc.users'));
    await expect(result.current.deleteUser(3)).rejects.toThrow('permission denied: bmc.users');
  });

  it('shows the server message of a refused listing', async () => {
    bmc.listUsers.mockResolvedValue(refused('permission denied: bmc.users'));
    const { result } = renderHook(() => useBMCUsers('7'));
    await waitFor(() => expect(result.current.error).toBe('permission denied: bmc.users'));
    expect(result.current.listed).toBe(false);
  });
});
