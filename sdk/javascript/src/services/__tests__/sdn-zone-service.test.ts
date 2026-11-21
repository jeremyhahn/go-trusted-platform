/**
 * Unit tests for the NetworkZone operations of the SDN service (#2065).
 *
 * The webservice serves the zones on the REST zone shape under
 * /api/v1/sdn/zones (pkg/webservice/v1/rest/sdn/zones.go registerZoneRoutes):
 * the create and update bodies are the zone spec itself, the name is the
 * path segment, and the list takes an optional `lifecycle_role` filter.
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

describe('SDNService NetworkZone operations', () => {
  let client: ApiClient;
  let service: SDNService;
  const response = { data: { marker: 'response' } };

  beforeEach(() => {
    client = createMockApiClient();
    for (const verb of ['get', 'post', 'put', 'delete'] as const) {
      vi.mocked(client[verb]).mockResolvedValue(response as never);
    }
    service = new SDNService(client);
  });

  it('lists the zones without a query when no role is given', async () => {
    const result = await service.listNetworkZones();

    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith('/v1/sdn/zones');
    expect(result).toBe(response);
  });

  it('lists the zones of one lifecycle role', async () => {
    const result = await service.listNetworkZones({ lifecycleRole: 'provisioning' });

    expect(client.get).toHaveBeenCalledTimes(1);
    expect(client.get).toHaveBeenCalledWith('/v1/sdn/zones?lifecycle_role=provisioning');
    expect(result).toBe(response);
  });

  it('creates a zone with the spec as the body', async () => {
    const spec = { name: 'lab', offset: 9, port_classes: ['hypervisor'] };

    const result = await service.createNetworkZone(spec);

    expect(client.post).toHaveBeenCalledTimes(1);
    expect(client.post).toHaveBeenCalledWith('/v1/sdn/zones', spec);
    expect(vi.mocked(client.post).mock.calls[0]?.[1]).toEqual({
      name: 'lab',
      offset: 9,
      port_classes: ['hypervisor'],
    });
    expect(result).toBe(response);
  });

  it('updates a zone under its escaped name', async () => {
    const result = await service.updateNetworkZone('lab a', { isolate: true });

    expect(client.put).toHaveBeenCalledTimes(1);
    expect(client.put).toHaveBeenCalledWith('/v1/sdn/zones/lab%20a', { isolate: true });
    expect(result).toBe(response);
  });

  it('deletes a zone under its escaped name', async () => {
    const result = await service.deleteNetworkZone('lab/a');

    expect(client.delete).toHaveBeenCalledTimes(1);
    expect(client.delete).toHaveBeenCalledWith('/v1/sdn/zones/lab%2Fa');
    expect(result).toBe(response);
  });
});
