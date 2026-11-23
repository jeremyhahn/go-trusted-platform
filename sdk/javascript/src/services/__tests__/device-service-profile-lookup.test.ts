/**
 * Unit tests for the DeviceService profile lookups: the response shape the
 * server sends and the wire names it decodes (#2048).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DeviceService } from '../device-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { DeviceProfile } from '../../types/device.js';

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

/**
 * The server answers the three profile lookups with the flat profile
 * (profileToResponse in pkg/webservice/v1/device/rest_handlers.go), not a
 * `{ profile }` wrapper, and decodes the match body as `mac_address`,
 * `serial` and `model` (pkg/webservice/v1/device/types.go).
 */
describe('DeviceService profile lookups', () => {
  let service: DeviceService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DeviceService(mockClient);
  });

  const flat = { success: true, data: { id: 3, name: 'edge', model: 'X11' } };

  it('findProfileByMACAddress returns the flat profile as data', async () => {
    vi.mocked(mockClient.get).mockResolvedValue(flat);

    const p: DeviceProfile | undefined = (await service.findProfileByMACAddress('02:00:00:00:00:01')).data;

    expect(p?.name).toBe('edge');
    expect(p?.id).toBe(3);
  });

  it('findProfileBySerial returns the flat profile as data', async () => {
    vi.mocked(mockClient.get).mockResolvedValue(flat);

    const p: DeviceProfile | undefined = (await service.findProfileBySerial('SN001')).data;

    expect(p?.name).toBe('edge');
    expect(p?.id).toBe(3);
  });

  it('findMatchingProfile posts mac_address, serial and model under the server wire names', async () => {
    vi.mocked(mockClient.post).mockResolvedValue(flat);

    const result = await service.findMatchingProfile({
      macAddress: '02:00:00:00:00:01',
      serial: 'SN001',
      model: 'X11',
    });
    const p: DeviceProfile | undefined = result.data;

    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/device/profiles/match', {
      mac_address: '02:00:00:00:00:01',
      serial: 'SN001',
      model: 'X11',
    });
    expect(p?.name).toBe('edge');
    expect(p?.id).toBe(3);
  });

  it('findMatchingProfile omits identifiers it was not given', async () => {
    vi.mocked(mockClient.post).mockResolvedValue(flat);

    await service.findMatchingProfile({ serial: 'SN001' });

    const [path, body] = vi.mocked(mockClient.post).mock.calls[0] as [string, Record<string, unknown>];
    expect(path).toBe('/v1/device/profiles/match');
    expect(body).toEqual({ serial: 'SN001' });
    expect(body).not.toHaveProperty('macAddress');
    expect(body).not.toHaveProperty('mac_address');
  });
});
