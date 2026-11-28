/**
 * Unit tests for the device profile assignment wire body.
 *
 * `pkg/webservice/v1/device/template_types.go` decodes the assign request
 * with snake_case names (`profile_id`, `ek_serial`, `mac_address`,
 * `ek_cert`, `device_id`), and encoding/json ignores the fields it does not
 * know, so a camelCase body reaches the server with no device identity.
 * These tests pin the snake_case body and the unassign call.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
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

describe('DeviceService profile assignment wire body', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
  });

  it('posts every set field with its snake_case wire name', async () => {
    await service.assignProfileToDevice({
      profileId: 7,
      ekSerial: 'ab01',
      macAddress: '02:00:00:00:00:01',
      ekCert: 'PEM',
      deviceId: '42',
    });

    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles/7/assign', {
      profile_id: 7,
      ek_serial: 'ab01',
      mac_address: '02:00:00:00:00:01',
      ek_cert: 'PEM',
      device_id: '42',
    });
  });

  it('leaves out the fields that are not set', async () => {
    await service.assignProfileToDevice({ profileId: 7, deviceId: '42' });

    const [path, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/v1/device/profiles/7/assign');
    expect(body).toEqual({ profile_id: 7, device_id: '42' });
    expect(Object.keys(body).sort()).toEqual(['device_id', 'profile_id']);
  });

  it('unassigns with an empty body and returns the response unchanged', async () => {
    const response = { success: true, data: { id: 7 } };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.unassignProfileFromDevice(7);

    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles/7/unassign', {});
    expect(result).toBe(response);
  });
});
