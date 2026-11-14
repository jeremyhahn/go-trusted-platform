import { describe, it, expect, vi, beforeEach } from 'vitest';
import { OverlayService } from './overlay-service.js';
import type { ApiClient } from '../client/api-client.js';
import type { CreateVNIRequest } from '../types/overlay.js';

function createMockClient(): ApiClient {
  return {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
  } as unknown as ApiClient;
}

describe('OverlayService', () => {
  let mockClient: ApiClient;
  let service: OverlayService;

  beforeEach(() => {
    mockClient = createMockClient();
    service = new OverlayService(mockClient);
  });

  describe('getStatus', () => {
    it('GETs /v1/overlay/status with no query or body', async () => {
      const response = { success: true, data: { status: {} } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getStatus()).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/status');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getStatus()).rejects.toBe(failure);
    });
  });

  describe('listVTEPs', () => {
    it('GETs /v1/overlay/vteps with no query or body', async () => {
      const response = { success: true, data: { vteps: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.listVTEPs()).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vteps');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listVTEPs()).rejects.toBe(failure);
    });
  });

  describe('getVTEP', () => {
    it('GETs /v1/overlay/vteps/{nodeId} with no query or body', async () => {
      const response = { success: true, data: { vtep: {} } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getVTEP('node-1')).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vteps/node-1');
    });

    it('percent-encodes the node ID as one path segment', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getVTEP('rack 1/node?2');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vteps/rack%201%2Fnode%3F2');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: overlay: vtep not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getVTEP('missing')).rejects.toBe(failure);
    });
  });

  describe('createVNI', () => {
    it('POSTs the request as the body to /v1/overlay/vnis', async () => {
      const request: CreateVNIRequest = {
        config: { vni: 5001, vlan: 101, name: 'tenant-a', labels: { env: 'dev' } },
      };
      const response = { success: true, data: { vni: request.config } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      await expect(service.createVNI(request)).resolves.toBe(response);

      expect(mockClient.post).toHaveBeenCalledTimes(1);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/overlay/vnis', {
        config: { vni: 5001, vlan: 101, name: 'tenant-a', labels: { env: 'dev' } },
      });
    });

    it('propagates a transport error', async () => {
      const failure = new Error('409 Conflict: overlay: vni exists');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.createVNI({ config: { vni: 5001 } })).rejects.toBe(failure);
    });
  });

  describe('listVNIs', () => {
    it('GETs /v1/overlay/vnis with no query or body', async () => {
      const response = { success: true, data: { vnis: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.listVNIs()).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/vnis');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listVNIs()).rejects.toBe(failure);
    });
  });

  describe('deleteVNI', () => {
    it('DELETEs /v1/overlay/vnis/{vni} with no query or body', async () => {
      const response = { success: true, data: {} };
      vi.mocked(mockClient.delete).mockResolvedValue(response);

      await expect(service.deleteVNI(5001)).resolves.toBe(response);

      expect(mockClient.delete).toHaveBeenCalledTimes(1);
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/overlay/vnis/5001');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: overlay: vni not found');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.deleteVNI(9999)).rejects.toBe(failure);
    });
  });

  describe('listTunnels', () => {
    it('GETs /v1/overlay/tunnels with the vni filter as the query', async () => {
      const response = { success: true, data: { tunnels: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.listTunnels({ vni: 5001 })).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/tunnels?vni=5001');
    });

    it('sends no query without a request or without a vni', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { tunnels: [] } });

      await service.listTunnels();
      await service.listTunnels({});

      expect(mockClient.get).toHaveBeenNthCalledWith(1, '/v1/overlay/tunnels');
      expect(mockClient.get).toHaveBeenNthCalledWith(2, '/v1/overlay/tunnels');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listTunnels({ vni: 5001 })).rejects.toBe(failure);
    });
  });

  describe('getTunnelStats', () => {
    it('GETs /v1/overlay/tunnels/stats with remote_vtep and vni query parameters', async () => {
      const response = { success: true, data: { stats: {} } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.getTunnelStats({ remoteVtep: 'vtep-b', vni: 5001 })).resolves.toBe(
        response
      );

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/tunnels/stats?remote_vtep=vtep-b&vni=5001');
    });

    it('percent-encodes the remote VTEP as a query value', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: {} });

      await service.getTunnelStats({ remoteVtep: 'fd00::1/64', vni: 7 });

      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/overlay/tunnels/stats?remote_vtep=fd00%3A%3A1%2F64&vni=7'
      );
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: overlay: tunnel not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getTunnelStats({ remoteVtep: 'vtep-x', vni: 1 })).rejects.toBe(failure);
    });
  });

  describe('listRemoteMACs', () => {
    it('GETs /v1/overlay/macs with the vni filter as the query', async () => {
      const response = { success: true, data: { entries: [] } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      await expect(service.listRemoteMACs({ vni: 5001 })).resolves.toBe(response);

      expect(mockClient.get).toHaveBeenCalledTimes(1);
      expect(mockClient.get).toHaveBeenCalledWith('/v1/overlay/macs?vni=5001');
    });

    it('sends no query without a request or without a vni', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { entries: [] } });

      await service.listRemoteMACs();
      await service.listRemoteMACs({});

      expect(mockClient.get).toHaveBeenNthCalledWith(1, '/v1/overlay/macs');
      expect(mockClient.get).toHaveBeenNthCalledWith(2, '/v1/overlay/macs');
    });

    it('propagates a transport error', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listRemoteMACs({ vni: 5001 })).rejects.toBe(failure);
    });
  });

  describe('forgetMAC', () => {
    it('DELETEs /v1/overlay/macs with the MAC percent-encoded in the query', async () => {
      const response = { success: true, data: {} };
      vi.mocked(mockClient.delete).mockResolvedValue(response);

      await expect(service.forgetMAC({ mac: '02:00:00:aa:bb:cc', vni: 5001 })).resolves.toBe(
        response
      );

      expect(mockClient.delete).toHaveBeenCalledTimes(1);
      expect(mockClient.delete).toHaveBeenCalledWith(
        '/v1/overlay/macs?mac=02%3A00%3A00%3Aaa%3Abb%3Acc&vni=5001'
      );
    });

    it('propagates a transport error', async () => {
      const failure = new Error('404 Not Found: overlay: mac not found');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.forgetMAC({ mac: '02:00:00:00:00:01', vni: 1 })).rejects.toBe(failure);
    });
  });
});
