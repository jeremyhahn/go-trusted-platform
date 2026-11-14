import { describe, expect, it } from 'vitest';
import { toAllocation, toPeer, toPrefix, unwrapPayload } from './use-gateway-bgp';

describe('use-gateway-bgp field mapping', () => {
  it('reads a peer in camelCase and in proto names', () => {
    expect(toPeer({ address: 'a', asn: 64513, state: 'established', prefixesReceived: 4 })).toEqual({
      address: 'a',
      asn: 64513,
      state: 'established',
      prefixesReceived: 4,
    });
    expect(toPeer({ address: 'b', asn: '64514', prefixes_received: '7' })).toEqual({
      address: 'b',
      asn: 64514,
      state: '',
      prefixesReceived: 7,
    });
  });

  it('reads a prefix next hop in either name', () => {
    expect(toPrefix({ prefix: 'p', nextHop: 'n1' }).nextHop).toBe('n1');
    expect(toPrefix({ prefix: 'p', next_hop: 'n2' }).nextHop).toBe('n2');
    expect(toPrefix({ prefix: 'p' }).nextHop).toBe('');
  });

  it('reads an allocation pool id in either name', () => {
    expect(toAllocation({ ip: 'i', poolId: 'p1', hostname: 'h', status: 'active' })).toEqual({
      ip: 'i',
      poolId: 'p1',
      deviceId: '',
      hostname: 'h',
      status: 'active',
    });
    expect(toAllocation({ ip: 'i', pool_id: 'p2' }).poolId).toBe('p2');
    expect(toAllocation({ ip: 'i', deviceId: 'd1' }).deviceId).toBe('d1');
    expect(toAllocation({ ip: 'i', device_id: 'd2' }).deviceId).toBe('d2');
  });

  it('unwraps the REST envelope payload', () => {
    expect(unwrapPayload({ code: 200, success: true, payload: { peers: [] } })).toEqual({ peers: [] });
    expect(unwrapPayload({ code: 503, success: false, error: 'x', payload: null })).toBeNull();
    expect(unwrapPayload({ peers: [] })).toEqual({ peers: [] });
  });
});
