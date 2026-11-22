/**
 * Unit tests for the GatewayService NAT64 status read on the webservice
 * (#2052).
 *
 * The webservice serves GetNAT64Status at `GET /api/v1/gateway/nat64/status`
 * (protojson camelCase). The daemon keeps its own snake_case route under
 * `/v1/sdn/gateway/nat64/status`, which getNAT64Status still reads.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { GatewayNAT64Status } from '../../types/gateway.js';

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

describe('GatewayService NAT64 status on the webservice', () => {
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

  it('getGatewayNAT64Status gets /v1/gateway/nat64/status', async () => {
    const response = {
      success: true,
      data: {
        status: {
          active: true,
          instancePresent: true,
          prefix: '64:ff9b::/96',
          instance: 'tp-nat64',
          sessions: '12',
          pool4Used: '3',
          flowCount: 2,
        },
      },
    };
    vi.mocked(mockClient.get).mockResolvedValue(response);

    const result = await service.getGatewayNAT64Status();

    expect(result).toBe(response);
    expectOnlyGet('/v1/gateway/nat64/status');
  });

  it('getGatewayNAT64Status types a never-reconciled status with lastReconcile null', async () => {
    // The webservice emits unpopulated fields: before the first reconcile the
    // timestamp arrives as null, and every scalar carries its zero value.
    const status: GatewayNAT64Status = {
      active: false,
      instancePresent: false,
      prefix: '',
      instance: '',
      sessions: '0',
      pool4Used: '0',
      moduleVersion: '',
      flowCount: 0,
      lastReconcile: null,
      lastError: '',
    };
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { status } });

    const result = await service.getGatewayNAT64Status();

    expect(result.data?.status?.lastReconcile).toBeNull();
    expectOnlyGet('/v1/gateway/nat64/status');
  });

  it('getNAT64Status still gets the daemon path', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

    await service.getNAT64Status();

    expectOnlyGet('/v1/sdn/gateway/nat64/status');
  });
});
