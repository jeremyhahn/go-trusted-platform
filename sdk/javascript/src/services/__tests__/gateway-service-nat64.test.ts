/**
 * Unit test for the NAT64 status route.
 *
 * `pkg/api/rest/gateway_nat64_handlers.go` serves
 * `GET /api/v1/sdn/gateway/nat64/status`. A client that requests a path the
 * server does not route gets a 404 that is indistinguishable from a gateway
 * with no translator configured, so the path is pinned here rather than
 * discovered in production (docs/gateway/api.md §5a).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
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

describe('GatewayService NAT64', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  it('gets the served /v1/sdn/gateway/nat64/status path', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: { active: true, instance_present: true, prefix: '64:ff9b::/96' },
    });

    const result = await service.getNAT64Status();

    expect(result.success).toBe(true);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/nat64/status');
  });

  it('surfaces a started translator whose kernel instance has gone', async () => {
    // The distinction the whole surface exists for: active but not present
    // means the instance disappeared underneath a started section, which is
    // not the same as a gateway that never configured one.
    vi.mocked(mockClient.get).mockResolvedValue({
      success: true,
      data: {
        active: true,
        instance_present: false,
        prefix: '64:ff9b::/96',
        instance: 'tp-nat64',
        last_error: 'instance vanished',
      },
    });

    const result = await service.getNAT64Status();

    expect(result.data?.active).toBe(true);
    expect(result.data?.instance_present).toBe(false);
    expect(result.data?.last_error).toBe('instance vanished');
  });
});
