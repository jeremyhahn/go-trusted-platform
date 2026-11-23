/**
 * OverlayService wire tests (#1722): each method calls the REST route the
 * server registers under /api/v1/overlay.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OverlayService } from '../overlay-service.js';
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

describe('OverlayService', () => {
  let service: OverlayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new OverlayService(mockClient);
  });

  it('listVTEPs GETs /vteps', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { vteps: [] } });
    await service.listVTEPs();
    expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vteps');
  });

  it('getVTEP GETs the encoded node under /vteps', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    await service.getVTEP('node a');
    expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vteps/node%20a');
  });

  it('deleteVNI DELETEs /vnis/{vni}', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });
    await service.deleteVNI(5001);
    expect(mockClient.delete).toHaveBeenCalledWith('/v1/overlay/vnis/5001');
  });

  it('listTunnels GETs /tunnels, filtered by VNI when given', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tunnels: [] } });
    await service.listTunnels();
    expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/tunnels');
    await service.listTunnels({ vni: 7 });
    expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/tunnels?vni=7');
  });

  it('getTunnelStats GETs /tunnels/stats with remote_vtep and vni', async () => {
    vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });
    await service.getTunnelStats({ remoteVtep: 'node-b', vni: 7 });
    expect(mockClient.get).toHaveBeenCalledWith(
      '/v1/overlay/tunnels/stats?remote_vtep=node-b&vni=7'
    );
  });

  it('forgetMAC DELETEs /macs with mac and vni', async () => {
    vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });
    await service.forgetMAC({ mac: 'aa:bb:cc:dd:ee:ff', vni: 7 });
    expect(mockClient.delete).toHaveBeenCalledWith(
      '/v1/overlay/macs?mac=aa%3Abb%3Acc%3Add%3Aee%3Aff&vni=7'
    );
  });

  it('propagates a transport error unchanged', async () => {
    const failure = new Error('404 Not Found: overlay: vni not found');
    vi.mocked(mockClient.delete).mockRejectedValue(failure);
    await expect(service.deleteVNI(9)).rejects.toBe(failure);
  });
});
