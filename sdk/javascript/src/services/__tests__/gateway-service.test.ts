/**
 * Unit tests for GatewayService (#1774).
 *
 * Every public method is driven against a mocked transport; each test
 * asserts the HTTP verb, the exact path (no Gateway method takes list
 * options, so no query string may appear) and the body, and a table at the
 * end checks that a transport rejection reaches the caller for every method.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ success: true, data: {} }),
    post: vi.fn().mockResolvedValue({ success: true, data: {} }),
    put: vi.fn().mockResolvedValue({ success: true, data: {} }),
    patch: vi.fn().mockResolvedValue({ success: true, data: {} }),
    delete: vi.fn().mockResolvedValue({ success: true, data: {} }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'http://localhost',
  } as unknown as ApiClient;
}

describe('GatewayService', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  function expectOnly(verb: 'get' | 'post' | 'delete'): void {
    for (const other of ['get', 'post', 'put', 'patch', 'delete'] as const) {
      if (other !== verb) {
        expect(mockClient[other]).not.toHaveBeenCalled();
      }
    }
    expect(mockClient[verb]).toHaveBeenCalledTimes(1);
  }

  describe('status', () => {
    it('getStatus GETs /v1/gateway/status and returns the response', async () => {
      const response = { success: true, data: { modes: 3 } };
      vi.mocked(mockClient.get).mockResolvedValue(response);

      const result = await service.getStatus();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/status');
      expect(result).toBe(response);
    });

    it('setMode POSTs the request as the body to /v1/gateway/mode', async () => {
      const response = { success: true, data: { modes: 5 } };
      vi.mocked(mockClient.post).mockResolvedValue(response);

      const result = await service.setMode({ modes: 5 });

      expectOnly('post');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/gateway/mode', { modes: 5 });
      expect(result).toBe(response);
    });
  });

  describe('telemetry state', () => {
    it('listState GETs /v1/gateway/state', async () => {
      await service.listState();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/state');
    });

    it('getState GETs /v1/gateway/state/{id} with the id encoded', async () => {
      await service.getState('gw/1 a?b');

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/state/gw%2F1%20a%3Fb');
    });

    it('deleteState DELETEs /v1/gateway/state/{id} with no body', async () => {
      await service.deleteState('example-gateway');

      expectOnly('delete');
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/gateway/state/example-gateway');
    });

    it('deleteState encodes the id', async () => {
      await service.deleteState('a/b');

      expect(mockClient.delete).toHaveBeenCalledWith('/v1/gateway/state/a%2Fb');
    });
  });

  describe('NAT64', () => {
    it('getNAT64Status GETs the absolute daemon path, not one under basePath', async () => {
      await service.getNAT64Status();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/nat64/status');
    });
  });

  describe('BGP', () => {
    it('getBGPStatus GETs /v1/gateway/bgp/status', async () => {
      await service.getBGPStatus();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/bgp/status');
    });

    it('listBGPPeers GETs /v1/gateway/bgp/peers', async () => {
      await service.listBGPPeers();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/bgp/peers');
    });

    it('announcePrefix POSTs the request as the body to /v1/gateway/bgp/prefixes', async () => {
      const request = { prefix: '2001:db8::/48', nextHop: '2001:db8::1' };

      await service.announcePrefix(request);

      expectOnly('post');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/gateway/bgp/prefixes', request);
    });

    // The router registers DELETE /gateway/bgp/prefixes and reads the CIDR
    // from the `prefix` query parameter (router.go withdrawPrefix).
    it('withdrawPrefix DELETEs /bgp/prefixes with the CIDR in the prefix query, encoded', async () => {
      await service.withdrawPrefix({ prefix: '10.0.0.0/24' });

      expectOnly('delete');
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/gateway/bgp/prefixes?prefix=10.0.0.0%2F24');
    });

    it('withdrawPrefix encodes an IPv6 CIDR in the query', async () => {
      await service.withdrawPrefix({ prefix: '2001:db8::/48' });

      expect(mockClient.delete).toHaveBeenCalledWith(
        '/v1/gateway/bgp/prefixes?prefix=2001%3Adb8%3A%3A%2F48'
      );
    });

    it('listAnnouncedPrefixes GETs /v1/gateway/bgp/prefixes', async () => {
      await service.listAnnouncedPrefixes();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/bgp/prefixes');
    });
  });

  describe('IPAM', () => {
    it('listIPAMPools GETs /v1/gateway/ipam/pools', async () => {
      await service.listIPAMPools();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/ipam/pools');
    });

    // The router registers POST /gateway/ipam/allocations and decodes an
    // AllocateIPRequest (pool_id, device_id, hostname) from the body.
    it('allocateIP POSTs /ipam/allocations with poolId, deviceId and hostname in the body', async () => {
      const request = { poolId: 'pool a', deviceId: 'dev-1', hostname: 'node-1' };
      await service.allocateIP(request);

      expectOnly('post');
      expect(mockClient.post).toHaveBeenCalledWith('/v1/gateway/ipam/allocations', {
        poolId: 'pool a',
        deviceId: 'dev-1',
        hostname: 'node-1',
      });
    });

    it('allocateIP sends the poolId alone when the optional fields are not given', async () => {
      await service.allocateIP({ poolId: 'p1' });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/gateway/ipam/allocations', { poolId: 'p1' });
    });

    // The router registers DELETE /gateway/ipam/allocations and reads the
    // address from the `ip` query parameter (router.go releaseIP).
    it('releaseIP DELETEs /ipam/allocations with the address in the ip query, encoded', async () => {
      await service.releaseIP({ ip: 'fd00::1' });

      expectOnly('delete');
      expect(mockClient.delete).toHaveBeenCalledWith('/v1/gateway/ipam/allocations?ip=fd00%3A%3A1');
    });

    it('listAllocations with no request GETs every allocation', async () => {
      await service.listAllocations();

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/ipam/allocations');
    });

    // The router registers only GET /gateway/ipam/allocations; the pool
    // filter goes in the poolId query parameter, never a /pools/{id} path.
    it('listAllocations with a pool id GETs /ipam/allocations with the poolId query, encoded', async () => {
      await service.listAllocations({ poolId: 'pool/1' });

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/ipam/allocations?poolId=pool%2F1');
    });

    it('listAllocations with an empty pool id GETs every allocation', async () => {
      await service.listAllocations({ poolId: '' });

      expectOnly('get');
      expect(mockClient.get).toHaveBeenCalledWith('/v1/gateway/ipam/allocations');
    });
  });

  describe('errors', () => {
    const cases: Array<[string, 'get' | 'post' | 'delete', (s: GatewayService) => Promise<unknown>]> = [
      ['getStatus', 'get', (s) => s.getStatus()],
      ['setMode', 'post', (s) => s.setMode({ modes: 1 })],
      ['listState', 'get', (s) => s.listState()],
      ['getState', 'get', (s) => s.getState('example-gateway')],
      ['deleteState', 'delete', (s) => s.deleteState('example-gateway')],
      ['getNAT64Status', 'get', (s) => s.getNAT64Status()],
      ['getBGPStatus', 'get', (s) => s.getBGPStatus()],
      ['listBGPPeers', 'get', (s) => s.listBGPPeers()],
      ['announcePrefix', 'post', (s) => s.announcePrefix({ prefix: '10.0.0.0/24' })],
      ['withdrawPrefix', 'delete', (s) => s.withdrawPrefix({ prefix: '10.0.0.0/24' })],
      ['listAnnouncedPrefixes', 'get', (s) => s.listAnnouncedPrefixes()],
      ['listIPAMPools', 'get', (s) => s.listIPAMPools()],
      ['allocateIP', 'post', (s) => s.allocateIP({ poolId: 'p1' })],
      ['releaseIP', 'delete', (s) => s.releaseIP({ ip: '10.0.0.5' })],
      ['listAllocations', 'get', (s) => s.listAllocations({ poolId: 'p1' })],
    ];

    it.each(cases)('%s propagates a transport rejection', async (_name, verb, call) => {
      const failure = new Error('transport down');
      vi.mocked(mockClient[verb]).mockRejectedValue(failure);

      await expect(call(service)).rejects.toBe(failure);
    });

    it.each(cases)('%s returns an unsuccessful response unchanged', async (_name, verb, call) => {
      const response = { success: false, error: { code: 'UNAVAILABLE', message: 'gateway not running' } };
      vi.mocked(mockClient[verb]).mockResolvedValue(response);

      await expect(call(service)).resolves.toBe(response);
    });
  });
});
