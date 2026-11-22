/**
 * Unit tests for the GatewayService load-balancer writes (#2052).
 *
 * The webservice serves them under `/api/v1/gateway/lb`, admin only:
 * `POST /lb/vips` (AddVIP), `DELETE /lb/vips/{protocol}/{address}/{port}`
 * (RemoveVIP) and `PUT /lb/vips/{protocol}/{address}/{port}/backends`
 * (SetVIPBackends). The paths are pinned here so a client never asks for a
 * route the server does not mount.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { VIPBackend, VIPConfig } from '../../types/gateway.js';

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

describe('GatewayService load balancer writes', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  const backend: VIPBackend = { address: '192.0.2.21', port: 8443, weight: 0 };
  const cfg: VIPConfig = {
    address: '192.0.2.10',
    port: 443,
    protocol: 'tcp',
    algorithm: 'hash',
    backends: [backend],
  };

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  function expectNoReads(): void {
    expect(mockClient.get).not.toHaveBeenCalled();
    expect(mockClient.patch).not.toHaveBeenCalled();
  }

  it('addVIP posts /v1/gateway/lb/vips with the VIP', async () => {
    const response = { success: true, data: { status: null, vip: null } };
    vi.mocked(mockClient.post).mockResolvedValue(response);

    const result = await service.addVIP(cfg);

    expect(result).toBe(response);
    expect(mockClient.post).toHaveBeenCalledTimes(1);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/gateway/lb/vips', { vip: cfg });
    expect(mockClient.put).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
    expectNoReads();
  });

  it('removeVIP deletes the VIP by protocol, address and port', async () => {
    const response = { success: true, data: { status: null } };
    vi.mocked(mockClient.delete).mockResolvedValue(response);

    const result = await service.removeVIP('tcp', '192.0.2.10', 443);

    expect(result).toBe(response);
    expect(mockClient.delete).toHaveBeenCalledTimes(1);
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/gateway/lb/vips/tcp/192.0.2.10/443');
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.put).not.toHaveBeenCalled();
    expectNoReads();
  });

  it('setVIPBackends puts the backend set on the VIP', async () => {
    const response = { success: true, data: { status: null, vip: null } };
    vi.mocked(mockClient.put).mockResolvedValue(response);

    const result = await service.setVIPBackends('tcp', '192.0.2.10', 443, [backend]);

    expect(result).toBe(response);
    expect(mockClient.put).toHaveBeenCalledTimes(1);
    expect(mockClient.put).toHaveBeenCalledWith('/v1/gateway/lb/vips/tcp/192.0.2.10/443/backends', {
      backends: [backend],
    });
    expect(mockClient.post).not.toHaveBeenCalled();
    expect(mockClient.delete).not.toHaveBeenCalled();
    expectNoReads();
  });
});
