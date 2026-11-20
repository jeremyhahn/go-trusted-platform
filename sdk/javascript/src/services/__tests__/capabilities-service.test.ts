/**
 * Unit tests for the capabilities service (GET /api/v1/capabilities,
 * pkg/webservice/v1/capabilities.go).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  CapabilitiesService,
  CAPABILITY_REASON_BLOCKED_INTEGRATION,
  CAPABILITY_REASON_NOT_CONFIGURED,
  CAPABILITY_REASON_UNIMPLEMENTED,
} from '../capabilities-service.js';
import type { CapabilitiesResponse } from '../capabilities-service.js';
import { CapabilitiesService as IndexedCapabilitiesService } from '../index.js';
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

describe('CapabilitiesService', () => {
  let service: CapabilitiesService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new CapabilitiesService(mockClient);
  });

  it('is exported from the services index', () => {
    expect(IndexedCapabilitiesService).toBe(CapabilitiesService);
  });

  it('exports the server reason constants', () => {
    expect(CAPABILITY_REASON_NOT_CONFIGURED).toBe('not-configured: ');
    expect(CAPABILITY_REASON_UNIMPLEMENTED).toBe('unimplemented');
    expect(CAPABILITY_REASON_BLOCKED_INTEGRATION).toBe('blocked: integration');
  });

  it('list gets /v1/capabilities and passes the typed response through', async () => {
    const body: CapabilitiesResponse = {
      capabilities: [
        { op: 'ntp', kind: 'service', service: 'ntp', enabled: true },
        {
          op: 'GET /api/v1/dns/zones',
          kind: 'route',
          service: 'dns',
          enabled: false,
          reason: CAPABILITY_REASON_NOT_CONFIGURED + 'dns',
        },
      ],
      total: 2,
      enabled: 1,
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: body });

    const result = await service.list();

    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/capabilities');
    expect(result.success).toBe(true);
    expect(result.data).toEqual(body);
    expect(result.data?.capabilities[1]?.reason).toBe('not-configured: dns');
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('401 Unauthorized');
    vi.mocked(mockClient.get).mockRejectedValue(failure);

    await expect(service.list()).rejects.toBe(failure);
  });
});
