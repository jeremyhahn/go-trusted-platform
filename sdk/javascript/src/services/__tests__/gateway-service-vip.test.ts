/**
 * Unit test for the gateway load balancer and performance routes (#2052).
 *
 * The daemon (`pkg/api/rest/gateway_{lb,perf}_handlers.go`) and the web
 * service (`pkg/webservice/v1/rest/gateway/lb.go`) both serve these under
 * `/api/v1/sdn/gateway/...`. A wrong path is a 404 that reads like "no VIPs",
 * so every method's verb, path and body is pinned here.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GatewayService } from '../gateway-service.js';
import type { ApiClient } from '../../client/api-client.js';

function createMockApiClient(): ApiClient {
  return {
    get: vi.fn().mockResolvedValue({ success: true, data: {} }),
    post: vi.fn().mockResolvedValue({ success: true, data: {} }),
    put: vi.fn().mockResolvedValue({ success: true, data: {} }),
    patch: vi.fn(),
    delete: vi.fn().mockResolvedValue({ success: true, data: {} }),
    head: vi.fn(),
    options: vi.fn(),
    fetch: vi.fn(),
    baseUrl: 'https://api.example.com',
  } as unknown as ApiClient;
}

const VIP_PATH = '/v1/sdn/gateway/lb/vips/tcp/198.51.100.20/8443';

describe('GatewayService VIPs, LB and perf', () => {
  let service: GatewayService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new GatewayService(mockClient);
  });

  it('addVIP posts the VIP config wrapped as {vip}', async () => {
    const vip = {
      address: '198.51.100.20',
      port: 8443,
      protocol: 'tcp',
      backends: [{ address: '10.0.0.11', port: 443 }],
    };
    await service.addVIP(vip);
    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/gateway/lb/vips', { vip });
  });

  it('listVIPs gets the VIP collection', async () => {
    await service.listVIPs();
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/lb/vips');
  });

  it('getVIP gets the VIP by protocol, address and port', async () => {
    await service.getVIP('198.51.100.20', 8443, 'tcp');
    expect(mockClient.get).toHaveBeenCalledWith(VIP_PATH);
  });

  it('removeVIP deletes the VIP by protocol, address and port', async () => {
    await service.removeVIP('198.51.100.20', 8443, 'tcp');
    expect(mockClient.delete).toHaveBeenCalledWith(VIP_PATH);
  });

  it('escapes an IPv6 VIP address in the path', async () => {
    await service.getVIP('2001:db8::1', 443, 'udp');
    expect(mockClient.get).toHaveBeenCalledWith(
      '/v1/sdn/gateway/lb/vips/udp/2001%3Adb8%3A%3A1/443'
    );
  });

  it('setVIPBackends puts only {backends} at the VIP backends path', async () => {
    const backends = [
      { address: '10.0.0.11', port: 443 },
      { address: '10.0.0.12', port: 443, weight: 2 },
    ];
    await service.setVIPBackends({
      address: '198.51.100.20',
      port: 8443,
      protocol: 'tcp',
      backends,
    });
    expect(mockClient.put).toHaveBeenCalledWith(`${VIP_PATH}/backends`, { backends });
  });

  it('getLBStatus gets the LB status path', async () => {
    await service.getLBStatus();
    expect(mockClient.get).toHaveBeenCalledWith('/v1/sdn/gateway/lb/status');
  });

  it('getPerfFlows posts to the perf flows path', async () => {
    await service.getPerfFlows();
    expect(mockClient.post).toHaveBeenCalledWith('/v1/sdn/gateway/perf/flows', {});
  });

  it('getPerfDatapath passes the bridge as a query parameter', async () => {
    await service.getPerfDatapath();
    expect(mockClient.get).toHaveBeenLastCalledWith('/v1/sdn/gateway/perf/datapath');
    await service.getPerfDatapath('br-int');
    expect(mockClient.get).toHaveBeenLastCalledWith('/v1/sdn/gateway/perf/datapath?bridge=br-int');
  });

  it('getPerfConntrack sends the zone only when one is given', async () => {
    await service.getPerfConntrack();
    expect(mockClient.get).toHaveBeenLastCalledWith('/v1/sdn/gateway/perf/conntrack');
    await service.getPerfConntrack(0);
    expect(mockClient.get).toHaveBeenLastCalledWith('/v1/sdn/gateway/perf/conntrack?zone=0');
    await service.getPerfConntrack(7);
    expect(mockClient.get).toHaveBeenLastCalledWith('/v1/sdn/gateway/perf/conntrack?zone=7');
  });
});
