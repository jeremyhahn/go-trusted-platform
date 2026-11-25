/**
 * Unit tests for the BMC user routes (pkg/webservice/v1/bmc/handler.go,
 * `/bmc/{profileID}/users...`).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BMCService } from '../bmc-service.js';
import { BMCService as IndexedBMCService } from '../index.js';
import { BMCService as RootBMCService } from '../../index.js';
import { PlatformClient } from '../../client/platform-client.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('BMCService users', () => {
  let service: BMCService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BMCService(mockClient);
  });

  it('listUsers gets /v1/bmc/{profileId}/users and returns the users', async () => {
    const user = { slot: 2, username: 'admin', enabled: true, privilege: 4, channel: 1 };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [user] });

    const result = await service.listUsers('9007199254740993');

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/bmc/9007199254740993/users');
    expect(result.success).toBe(true);
    expect(result.data?.[0]).toEqual(user);
  });

  it('createUser posts /v1/bmc/{profileId}/users with enabled and channel defaulted', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({
      success: true,
      data: { slot: 3, username: 'ops', enabled: true, privilege: 3, channel: 1 },
    });

    await service.createUser(5, { slot: 3, username: 'ops', password: 'pw', privilege: 'operator' });

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[0]).toBe('/v1/bmc/5/users');
    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toEqual({
      slot: 3,
      username: 'ops',
      password: 'pw',
      privilege: 'operator',
      enabled: true,
      channel: 1,
    });
  });

  it('createUser sends given enabled and channel as is', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

    await service.createUser(5, {
      slot: 4,
      username: 'cb',
      password: 'pw',
      privilege: 'callback',
      enabled: false,
      channel: 2,
    });

    expect(vi.mocked(mockClient.post).mock.calls[0]?.[1]).toEqual({
      slot: 4,
      username: 'cb',
      password: 'pw',
      privilege: 'callback',
      enabled: false,
      channel: 2,
    });
  });

  it('deleteUser deletes /v1/bmc/{profileId}/users/{slot}', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.deleteUser(5, 3);

    expect(mockClient.delete).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.delete).mock.calls[0]?.[0]).toBe('/v1/bmc/5/users/3');
  });

  it('setUserPassword puts /v1/bmc/{profileId}/users/{slot}/password', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.setUserPassword(5, 3, 'new');

    expect(mockClient.put).toHaveBeenCalledTimes(1);
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[0]).toBe('/v1/bmc/5/users/3/password');
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[1]).toEqual({ password: 'new' });
  });

  it('setUserPrivilege puts /v1/bmc/{profileId}/users/{slot}/privilege with channel 1 by default', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.setUserPrivilege(5, 3, 'user');
    await service.setUserPrivilege(5, 3, 'administrator', 2);

    expect(mockClient.put).toHaveBeenCalledTimes(2);
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[0]).toBe('/v1/bmc/5/users/3/privilege');
    expect(vi.mocked(mockClient.put).mock.calls[0]?.[1]).toEqual({ privilege: 'user', channel: 1 });
    expect(vi.mocked(mockClient.put).mock.calls[1]?.[0]).toBe('/v1/bmc/5/users/3/privilege');
    expect(vi.mocked(mockClient.put).mock.calls[1]?.[1]).toEqual({
      privilege: 'administrator',
      channel: 2,
    });
  });

  it('passes an error answer through unchanged', async () => {
    const failure = {
      success: false,
      error: { code: 'NOT_FOUND', message: 'no profile', status: 404 },
    };
    vi.mocked(mockClient.get).mockResolvedValue(failure);

    const result = await service.listUsers(5);

    expect(result).toEqual(failure);
  });

  it('is exported from the services index and package root and served as client.bmc', () => {
    expect(IndexedBMCService).toBe(BMCService);
    expect(RootBMCService).toBe(BMCService);
    const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
    expect(client.bmc).toBeInstanceOf(BMCService);
  });
});

describe('BMCService profile ID and slot validation', () => {
  let service: BMCService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new BMCService(mockClient);
  });

  const malformed = ['42/../43', '1e3', '-1', '18446744073709551616', 'abc'];
  const req = { slot: 3, username: 'ops', password: 'pw', privilege: 'user' as const };

  for (const id of malformed) {
    it(`refuses profile ID ${JSON.stringify(id)} with no request`, async () => {
      await expect(service.listUsers(id)).rejects.toThrow(TypeError);
      await expect(service.createUser(id, req)).rejects.toThrow(TypeError);
      await expect(service.deleteUser(id, 3)).rejects.toThrow(TypeError);
      await expect(service.setUserPassword(id, 3, 'pw')).rejects.toThrow(TypeError);
      await expect(service.setUserPrivilege(id, 3, 'user')).rejects.toThrow(TypeError);
      expect(mockClient.get).not.toHaveBeenCalled();
      expect(mockClient.post).not.toHaveBeenCalled();
      expect(mockClient.put).not.toHaveBeenCalled();
      expect(mockClient.delete).not.toHaveBeenCalled();
    });
  }

  for (const slot of [-1, 256, 1.5, Number.NaN]) {
    it(`refuses slot ${String(slot)} with no request`, async () => {
      await expect(service.deleteUser(42, slot)).rejects.toThrow(TypeError);
      await expect(service.setUserPassword(42, slot, 'pw')).rejects.toThrow(TypeError);
      await expect(service.setUserPrivilege(42, slot, 'user')).rejects.toThrow(TypeError);
      expect(mockClient.put).not.toHaveBeenCalled();
      expect(mockClient.delete).not.toHaveBeenCalled();
    });
  }

  it('a decimal ID and slot still build /v1/bmc/42/...', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: [] });
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: { status: 'ok' } });

    await service.listUsers('42');
    await service.deleteUser(42, 255);

    expect(vi.mocked(mockClient.get).mock.calls[0]?.[0]).toBe('/v1/bmc/42/users');
    expect(vi.mocked(mockClient.delete).mock.calls[0]?.[0]).toBe('/v1/bmc/42/users/255');
  });
});
