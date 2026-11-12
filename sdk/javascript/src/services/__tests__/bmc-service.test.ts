/**
 * BMCService wire tests (#1720): each method sends the verb, path and
 * body the REST handlers in pkg/webservice/v1/bmc decode.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ApiClient } from '../../client/api-client.js';
import { BMCService, bmcPrivilegeName } from '../bmc-service.js';
import {
  BMCService as RootBMCService,
  BMC_PRIVILEGE_CODES as RootBMCPrivilegeCodes,
  bmcPrivilegeName as rootBMCPrivilegeName,
  PlatformClient,
} from '../../index.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ data: [] }),
    post: vi.fn().mockResolvedValue({ data: {} }),
    put: vi.fn().mockResolvedValue({ data: { status: 'ok' } }),
    patch: vi.fn(),
    delete: vi.fn().mockResolvedValue({ data: { status: 'ok' } }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

describe('BMCService', () => {
  let client: ApiClient;
  let service: BMCService;

  beforeEach(() => {
    client = createMockApiClient();
    service = new BMCService(client);
  });

  it('listUsers GETs /v1/bmc/{profileID}/users', async () => {
    await service.listUsers(7);
    expect(client.get).toHaveBeenCalledWith('/v1/bmc/7/users');
  });

  it('createUser POSTs the snake_case body to /v1/bmc/{profileID}/users', async () => {
    await service.createUser(7, {
      slot: 3,
      username: 'ops',
      password: 'pw',
      privilege: 'operator',
      enabled: true,
      channel: 1,
    });
    expect(client.post).toHaveBeenCalledWith('/v1/bmc/7/users', {
      slot: 3,
      username: 'ops',
      password: 'pw',
      privilege: 'operator',
      enabled: true,
      channel: 1,
    });
  });

  it('deleteUser DELETEs /v1/bmc/{profileID}/users/{slot}', async () => {
    await service.deleteUser(7, 3);
    expect(client.delete).toHaveBeenCalledWith('/v1/bmc/7/users/3');
  });

  it('setUserPassword PUTs the password to the slot', async () => {
    await service.setUserPassword(7, 3, 'new');
    expect(client.put).toHaveBeenCalledWith('/v1/bmc/7/users/3/password', { password: 'new' });
  });

  it('setUserPrivilege PUTs privilege and channel to the slot', async () => {
    await service.setUserPrivilege(7, 3, 'administrator', 1);
    expect(client.put).toHaveBeenCalledWith('/v1/bmc/7/users/3/privilege', {
      privilege: 'administrator',
      channel: 1,
    });
  });

  it('replaceWebCertificate PUTs cert_pem and key_pem to /cert', async () => {
    await service.replaceWebCertificate(7, { certPem: 'C', keyPem: 'K' });
    expect(client.put).toHaveBeenCalledWith('/v1/bmc/7/cert', { cert_pem: 'C', key_pem: 'K' });
  });

  it('bmcPrivilegeName maps IPMI codes and names', () => {
    expect(bmcPrivilegeName(0x04)).toBe('administrator');
    expect(bmcPrivilegeName(0x0f)).toBe('no-access');
    expect(bmcPrivilegeName('operator')).toBe('operator');
    expect(bmcPrivilegeName(0x09)).toBe('unknown');
  });
});

describe('BMC through the package root', () => {
  it('exports BMCService and its helpers from the root entry point', () => {
    expect(RootBMCService).toBe(BMCService);
    expect(rootBMCPrivilegeName).toBe(bmcPrivilegeName);
    expect(RootBMCPrivilegeCodes.administrator).toBe(4);
  });

  it('constructs client.bmc as a BMCService', () => {
    const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
    expect(client.bmc).toBeInstanceOf(RootBMCService);
  });
});
