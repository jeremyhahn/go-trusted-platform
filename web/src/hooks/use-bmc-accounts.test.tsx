import type { ReactNode } from 'react';
import { act, cleanup, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ApiResponse } from 'trusted-platform-sdk';

import { ok, refused, stubControlPlane, withControlPlane } from '@/test/control-plane-fetch';
import {
  bmcPrivilegeName,
  bmcUsersPath,
  useBMCAccounts,
  type BMCPrivilegeName,
  type BMCStatusOK,
  type BMCUser,
} from './use-bmc-accounts';

// #2040: the BMC accounts hook drives ListUsers, CreateUser, DeleteUser,
// SetUserPassword and SetUserPrivilege through the real SDK API client;
// fetch is the only stub.

const wrapper = ({ children }: { children: ReactNode }) => withControlPlane(children);

function renderAccounts(profileID = '42') {
  return renderHook(() => useBMCAccounts(profileID), { wrapper });
}

describe('useBMCAccounts', () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('lists the users with their privilege names', async () => {
    const sent = stubControlPlane({
      'GET /api/v1/bmc/42/users': ok([
        { slot: 2, username: 'admin', enabled: true, privilege: 4, channel: 1 },
        { slot: 3, username: 'ops', enabled: false, privilege: 3, channel: 1 },
      ]),
    });
    const { result } = renderAccounts();
    let res: ApiResponse<BMCUser[]> | undefined;
    await act(async () => {
      res = await result.current.listUsers();
    });
    expect(res?.data).toHaveLength(2);
    expect(res!.data!.map((u) => bmcPrivilegeName(u.privilege))).toEqual(['administrator', 'operator']);
    expect(sent).toEqual([{ method: 'GET', path: '/api/v1/bmc/42/users', body: undefined }]);
  });

  it('creates a user with the defaults filled', async () => {
    const sent = stubControlPlane({
      'POST /api/v1/bmc/42/users': ok({ slot: 5, username: 'svc', enabled: true, privilege: 2, channel: 1 }),
    });
    const { result } = renderAccounts();
    let res: ApiResponse<BMCUser> | undefined;
    await act(async () => {
      res = await result.current.createUser({ slot: 5, username: ' svc ', password: 's3cret', privilege: 'user' });
    });
    expect(sent[0].body).toEqual({
      slot: 5,
      username: 'svc',
      password: 's3cret',
      privilege: 'user',
      enabled: true,
      channel: 1,
    });
    expect(res?.data?.slot).toBe(5);
  });

  it('surfaces a refused create', async () => {
    stubControlPlane({
      'POST /api/v1/bmc/42/users': refused(400, 'bmc: password is required'),
    });
    const { result } = renderAccounts();
    let res: ApiResponse<BMCUser> | undefined;
    await act(async () => {
      res = await result.current.createUser({ slot: 5, username: 'svc', password: '', privilege: 'user' });
    });
    expect(res?.success).toBe(false);
    expect(res?.error?.status).toBe(400);
    expect(res?.error?.message).toContain('password is required');
  });

  it('deletes a user by slot', async () => {
    const sent = stubControlPlane({
      'DELETE /api/v1/bmc/42/users/5': ok({ status: 'ok' }),
    });
    const { result } = renderAccounts();
    let res: ApiResponse<BMCStatusOK> | undefined;
    await act(async () => {
      res = await result.current.deleteUser(5);
    });
    expect(sent[0]).toMatchObject({ method: 'DELETE', path: '/api/v1/bmc/42/users/5' });
    expect(res?.data?.status).toBe('ok');
  });

  it('sets a password', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/bmc/42/users/5/password': ok({ status: 'ok' }),
    });
    const { result } = renderAccounts();
    await act(async () => {
      await result.current.setPassword(5, 'n3w');
    });
    expect(sent[0].body).toEqual({ password: 'n3w' });
  });

  it('sets a privilege and surfaces an invalid one', async () => {
    const sent = stubControlPlane({
      'PUT /api/v1/bmc/42/users/5/privilege': ok({ status: 'ok' }),
    });
    const { result } = renderAccounts();
    await act(async () => {
      await result.current.setPrivilege(5, 'operator');
    });
    expect(sent[0].body).toEqual({ privilege: 'operator', channel: 1 });

    vi.unstubAllGlobals();
    stubControlPlane({
      'PUT /api/v1/bmc/42/users/5/privilege': refused(400, 'bmc: invalid privilege: root'),
    });
    let res: ApiResponse<BMCStatusOK> | undefined;
    await act(async () => {
      res = await result.current.setPrivilege(5, 'root' as BMCPrivilegeName);
    });
    expect(res?.error?.status).toBe(400);
  });

  it('names privileges and builds the paths', () => {
    expect(bmcPrivilegeName(1)).toBe('callback');
    expect(bmcPrivilegeName(2)).toBe('user');
    expect(bmcPrivilegeName(15)).toBe('no-access');
    expect(bmcPrivilegeName(9)).toBe('unknown(9)');
    expect(bmcUsersPath('7')).toBe('/v1/bmc/7/users');
    expect(bmcUsersPath('7', 3, 'password')).toBe('/v1/bmc/7/users/3/password');
    expect(bmcUsersPath('a/b', 0)).toBe('/v1/bmc/a%2Fb/users/0');
  });
});
