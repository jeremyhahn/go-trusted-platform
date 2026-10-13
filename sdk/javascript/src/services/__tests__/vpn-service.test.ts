/**
 * Unit tests for the VPN operator control plane client.
 *
 * Each operation is pinned to the REST route and verb in docs/vpn/api.md §1:
 * pkg/webservice/v1/rest/vpn registers exact verbs, and mux answers a wrong
 * verb on a known path with 404, so a drifted verb reads as a missing route.
 * Bodies are the camelCase protojson the server decodes.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { VPNService } from '../vpn-service.js';
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

describe('VPNService', () => {
  let service: VPNService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new VPNService(mockClient);
  });

  describe('enrolPeer', () => {
    it('POSTs the peer to /peers', async () => {
      const peer = {
        tenantId: 'acme',
        deviceId: 'laptop-1',
        zones: ['management'],
        enrolledAtUnix: '1760300000',
      };
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { peer } });

      const result = await service.enrolPeer({
        tenantId: 'acme',
        deviceId: 'laptop-1',
        zones: ['management'],
      });

      expect(result.data?.peer).toEqual(peer);
      expect(mockClient.post).toHaveBeenCalledWith('/v1/vpn/peers', {
        tenantId: 'acme',
        deviceId: 'laptop-1',
        zones: ['management'],
      });
    });

    it('sends an empty zone list when none is given', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: { peer: {} } });

      await service.enrolPeer({ tenantId: 'acme', deviceId: 'laptop-1' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/vpn/peers', {
        tenantId: 'acme',
        deviceId: 'laptop-1',
        zones: [],
      });
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: vpn: device id is required');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.enrolPeer({ tenantId: 'acme', deviceId: '' })).rejects.toBe(failure);
    });
  });

  describe('listPeers', () => {
    it('GETs /peers filtered by tenant', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { peers: [] } });

      await service.listPeers('acme');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vpn/peers?tenant_id=acme');
    });

    it('leaves the tenant filter off to list every tenant', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { peers: [] } });

      await service.listPeers();
      await service.listPeers('');

      expect(mockClient.get).toHaveBeenNthCalledWith(1, '/v1/vpn/peers');
      expect(mockClient.get).toHaveBeenNthCalledWith(2, '/v1/vpn/peers');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listPeers('acme')).rejects.toBe(failure);
    });
  });

  describe('revokePeer', () => {
    it('DELETEs the encoded device under its tenant', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });

      await service.revokePeer('acme corp', 'laptop/1');

      expect(mockClient.delete).toHaveBeenCalledWith(
        '/v1/vpn/peers/laptop%2F1?tenant_id=acme+corp'
      );
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: vpn: peer not found');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.revokePeer('acme', 'laptop-9')).rejects.toBe(failure);
    });
  });

  describe('getStatus', () => {
    it('GETs /status for one gateway', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { gateways: [] } });

      await service.getStatus('gw-01');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vpn/status?gateway_id=gw-01');
    });

    it('leaves the gateway filter off to report every gateway', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { gateways: [] } });

      await service.getStatus();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vpn/status');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: vpn: gateway not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getStatus('gw-404')).rejects.toBe(failure);
    });
  });

  describe('getPosturePolicy', () => {
    it('GETs the encoded policy under its tenant', async () => {
      const policy = {
        tenantId: 'acme',
        name: 'corp',
        module: 'package vpn.posture',
        updatedAtUnix: '1',
      };
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { policy } });

      const result = await service.getPosturePolicy('acme', 'corp v2');

      expect(result.data?.policy).toEqual(policy);
      expect(mockClient.get).toHaveBeenCalledWith(
        '/v1/vpn/posture-policies/corp%20v2?tenant_id=acme'
      );
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: vpn: posture policy not found');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.getPosturePolicy('acme', 'missing')).rejects.toBe(failure);
    });
  });

  describe('setPosturePolicy', () => {
    const request = { tenantId: 'acme', name: 'corp', module: 'package vpn.posture\n' };

    it('PUTs the policy to its name, with the name repeated in the body', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: { policy: request } });

      await service.setPosturePolicy(request);

      expect(mockClient.put).toHaveBeenCalledWith('/v1/vpn/posture-policies/corp', {
        tenantId: 'acme',
        name: 'corp',
        module: 'package vpn.posture\n',
      });
      expect(mockClient.post).not.toHaveBeenCalled();
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: vpn: invalid posture policy');
      vi.mocked(mockClient.put).mockRejectedValue(failure);

      await expect(service.setPosturePolicy(request)).rejects.toBe(failure);
    });
  });

  describe('deletePosturePolicy', () => {
    it('DELETEs the encoded policy under its tenant', async () => {
      vi.mocked(mockClient.delete).mockResolvedValue({ success: true, data: {} });

      await service.deletePosturePolicy('acme', 'corp');

      expect(mockClient.delete).toHaveBeenCalledWith(
        '/v1/vpn/posture-policies/corp?tenant_id=acme'
      );
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: vpn: posture policy not found');
      vi.mocked(mockClient.delete).mockRejectedValue(failure);

      await expect(service.deletePosturePolicy('acme', 'missing')).rejects.toBe(failure);
    });
  });

  describe('listPosturePolicies', () => {
    it('GETs /posture-policies filtered by tenant', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { policies: [] } });

      await service.listPosturePolicies('acme');

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vpn/posture-policies?tenant_id=acme');
    });

    it('leaves the tenant filter off to list every tenant', async () => {
      vi.mocked(mockClient.get).mockResolvedValue({ success: true, data: { policies: [] } });

      await service.listPosturePolicies();

      expect(mockClient.get).toHaveBeenCalledWith('/v1/vpn/posture-policies');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('503 Service Unavailable');
      vi.mocked(mockClient.get).mockRejectedValue(failure);

      await expect(service.listPosturePolicies('acme')).rejects.toBe(failure);
    });
  });
});
