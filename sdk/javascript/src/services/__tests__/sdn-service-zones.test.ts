/**
 * Unit tests for the SDNService network zone methods.
 *
 * The routes are served by pkg/webservice/v1/rest/sdn/zones.go
 * (registerZoneRoutes) under `/api/v1/sdn`, and the handler decodes the
 * snake_case JSON body as is.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SDNService } from '../sdn-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type {
  CreateNetworkZoneRequest,
  ListNetworkZonesResponse,
  NetworkZoneDeleteResponse,
  UpdateNetworkZoneRequest,
} from '../../types/sdn-zones.js';

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
  let service: SDNService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new SDNService(mockClient);
  });

  it('lists zones on GET /v1/sdn/zones', async () => {
    const data: ListNetworkZonesResponse = {
      zones: [
        {
          name: 'lab',
          offset: 9,
          created_at: '2026-11-23T00:00:00Z',
          updated_at: '2026-11-23T00:00:00Z',
        },
      ],
      count: 1,
      timestamp: '2026-11-23T00:00:00Z',
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data });

    const result = await service.listNetworkZones();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/zones');
    expect(result.data?.zones[0]?.name).toBe('lab');
  });

  it('narrows the list by lifecycle_role', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.listNetworkZones({ lifecycleRole: 'provisioning' });

    const url = vi.mocked(mockClient.get).mock.calls[0]?.[0] ?? '';
    const [path = '', query = ''] = url.split('?');
    expect(path).toBe('/v1/sdn/zones');
    expect(Object.fromEntries(new URLSearchParams(query))).toEqual({
      lifecycle_role: 'provisioning',
    });
  });

  it('creates a zone on POST /v1/sdn/zones with the snake_case body the handler decodes', async () => {
    vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
    const zone: CreateNetworkZoneRequest = {
      name: 'lab',
      offset: 9,
      port_classes: ['access'],
      allow_to: [{ zone: 'fabric', services: ['dns'] }],
    };

    await service.createNetworkZone(zone);

    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/zones', {
      name: 'lab',
      offset: 9,
      port_classes: ['access'],
      allow_to: [{ zone: 'fabric', services: ['dns'] }],
    });
  });

  it('updates a zone on PUT /v1/sdn/zones/{name} with the name encoded', async () => {
    vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });
    const zone: UpdateNetworkZoneRequest = { offset: 10, isolate: true };

    await service.updateNetworkZone('lab a', zone);

    expect(mockClient.put).toHaveBeenCalledWith('/v1/sdn/zones/lab%20a', {
      offset: 10,
      isolate: true,
    });
  });

  it('deletes a zone on DELETE /v1/sdn/zones/{name}', async () => {
    const data: NetworkZoneDeleteResponse = { deleted: true, restart_required: true };
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data });

    const result = await service.deleteNetworkZone('lab');

    expect(mockClient.delete).toHaveBeenCalledWith('/v1/sdn/zones/lab');
    expect(result.data?.restart_required).toBe(true);
  });
});
