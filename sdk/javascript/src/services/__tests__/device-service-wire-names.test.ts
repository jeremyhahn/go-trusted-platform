/**
 * Unit tests for the device profile write bodies.
 *
 * `pkg/webservice/v1/device/rest_handlers.go` decodes a flat ProfileRequest
 * with encoding/json, which ignores fields it does not know, and
 * `profile_mapping.go` reads an auth method other than '802.1x' as no
 * authentication. These tests pin the flat body and every auth method.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { AuthMethod, DeviceProfile } from '../../types/device.js';

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

const authMethods: Array<[AuthMethod, Record<string, string>]> = [
  ['UNSPECIFIED', {}],
  ['NONE', { auth_method: 'none' }],
  ['802_1X', { auth_method: '802.1x' }],
];

describe('DeviceService profile write bodies', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });
  });

  it.each(authMethods)('createProfile sends auth method %s as %o', async (authMethod, wire) => {
    await service.createProfile({
      profile: { name: 'p1', networks: { trusted: { vlan: 20, auth_method: authMethod } } },
    });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles', {
      name: 'p1',
      networks: { trusted: { vlan: 20, ...wire } },
    });
  });

  it.each(authMethods)('updateProfile sends auth method %s as %o', async (authMethod, wire) => {
    const profile: DeviceProfile = {
      id: '7',
      name: 'p1',
      role: 'worker',
      networks: { provisioning: { vlan: 10, auth_method: authMethod } },
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
    };
    await service.updateProfile({ profile });

    expect(mockClient.put).toHaveBeenCalledWith('/v1/device/profiles/7', {
      id: '7',
      name: 'p1',
      role: 'worker',
      networks: { provisioning: { vlan: 10, ...wire } },
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
    });
  });

  it('sends the firewall zone under the zone name the server reads', async () => {
    await service.createProfile({
      profile: { name: 'p1', networks: { trusted: { vlan: 20, firewallZone: 'lan' } } },
    });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles', {
      name: 'p1',
      networks: { trusted: { vlan: 20, zone: 'lan' } },
    });
  });

  it('sends a profile without networks unchanged and unwrapped', async () => {
    await service.createProfile({ profile: { name: 'p1', model: 'm1', enrollment_network: 'provisioning' } });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles', {
      name: 'p1',
      model: 'm1',
      enrollment_network: 'provisioning',
    });
  });
});
