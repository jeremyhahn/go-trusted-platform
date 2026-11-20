/**
 * SDNService network-zone methods (#2065): the REST routes
 * POST/GET /v1/sdn/zones and PUT/DELETE /v1/sdn/zones/{name}
 * (pkg/webservice/v1/rest/sdn/zones.go), snake_case bodies.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from '../sdn-service.js';
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

describe('SDNService network zones', () => {
  let mockClient: ApiClient;
  let service: SDNService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    for (const m of ['get', 'post', 'put', 'delete'] as const) {
      vi.mocked(mockClient[m]).mockResolvedValue({ success: true, data: {} });
    }
    service = new SDNService(mockClient);
  });

  it('listNetworkZones GETs /zones', async () => {
    await service.listNetworkZones();
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/zones');
  });

  it('listNetworkZones filters by lifecycle_role', async () => {
    await service.listNetworkZones({ lifecycleRole: 'staging' });
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/zones?lifecycle_role=staging');
  });

  it('createNetworkZone POSTs the zone body once, without retries', async () => {
    const zone = {
      name: 'lab',
      offset: 30,
      port_classes: ['lab'],
      allow_to: [{ zone: 'mgmt', services: ['ssh'] }],
    };
    await service.createNetworkZone(zone);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/zones', zone, { retry: { enabled: false } });
  });

  it('updateNetworkZone PUTs to the escaped zone name', async () => {
    await service.updateNetworkZone('lab/1', { offset: 31 });
    expect(mockClient.put).toHaveBeenCalledWith('/v1/sdn/zones/lab%2F1', { offset: 31 });
  });

  it('deleteNetworkZone DELETEs the escaped zone name', async () => {
    await service.deleteNetworkZone('lab 1');
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/sdn/zones/lab%201');
  });
});
