/**
 * Unit tests for the GatewayService load-balancer reads (#2052).
 *
 * The webservice serves them under `/api/v1/gateway/lb` (protojson
 * camelCase): `GET /lb/vips`, `GET /lb/vips/{protocol}/{address}/{port}` and
 * `GET /lb/status`. The paths are pinned here so a client never asks for a
 * route the server does not mount.
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

describe('GatewayService load balancer reads', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  function expectOnlyGet(path: string): void {
    expect(mockClient.get).toHaveBeenCalledTimes(1);
    expect(mockClient.get).toHaveBeenCalledWith(path);
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.patch).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
  }

  it('listVIPs gets /v1/gateway/lb/vips', async () => {
    const response = { success: true, data: { vips: [] } };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.listVIPs();

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/lb/vips');
  });

  it('getVIP gets the VIP by protocol, address and port', async () => {
    const response = { success: true, data: { vip: null } };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getVIP('tcp', '10.0.0.5', 443);

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/lb/vips/tcp/10.0.0.5/443');
  });

  it('getVIP encodes an IPv6 address', async () => {
    const response = { success: true, data: { vip: null } };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getVIP('udp', 'fd00::5', 53);

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/lb/vips/udp/fd00%3A%3A5/53');
  });

  it('getLBStatus gets /v1/gateway/lb/status', async () => {
    const response = {
      success: true,
      data: {
        status: {
          active: true,
          vipCount: 1,
          healthyBackends: 1,
          totalBackends: 2,
          lastReconcile: null,
        },
      },
    };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getLBStatus();

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/lb/status');
  });
});
