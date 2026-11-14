import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DNSService } from './dns-service.js';
import type { ApiClient } from '../client/api-client.js';
import type { DNSRecord } from '../types/dns.js';

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
  } as unknown as ApiClient;
}

const oldRecord: DNSRecord = { type: 'A', a: { name: 'svc', value: 'ip-1', ttl: 300 } };
const newRecord: DNSRecord = { type: 'A', a: { name: 'svc', value: 'ip-2', ttl: 600 } };

type Verb = 'get' | 'post' | 'put' | 'delete';

describe('DNSService', () => {
  let mockClient: ApiClient;
  let service: DNSService;

  beforeEach(() => {
    mockClient = createMockApiClient();
    for (const verb of ['get', 'post', 'put', 'delete'] as const) {
      vi.mocked(mockClient[verb]).mockResolvedValue({ success: true, data: {} });
    }
    service = new DNSService(mockClient);
  });

  function onlyCall(verb: Verb): unknown[] {
    for (const other of ['get', 'post', 'put', 'delete'] as const) {
      if (other !== verb) {
        expect(mockClient[other]).not.toHaveBeenCalled();
      }
    }
    expect(mockClient[verb]).toHaveBeenCalledTimes(1);
    return vi.mocked(mockClient[verb]).mock.calls[0] as unknown[];
  }

  describe('zones', () => {
    it('createZone posts the whole request to /v1/dns/zones', async () => {
      const request = { name: 'zone-a', ttl: 3600, description: 'd', internal: true };
      const response = await service.createZone(request);

      expect(onlyCall('post')).toEqual(['/v1/dns/zones', request]);
      expect(response).toEqual({ success: true, data: {} });
    });

    it('getZone gets the zone by its encoded name', async () => {
      await service.getZone('zone a/b');

      expect(onlyCall('get')).toEqual(['/v1/dns/zones/zone%20a%2Fb']);
    });

    it('listZones sends no query when the caller supplied no request', async () => {
      await service.listZones();

      expect(onlyCall('get')).toEqual(['/v1/dns/zones']);
    });

    it('listZones maps pageSize to limit and the visibility flags to strings', async () => {
      await service.listZones({ page: 2, pageSize: 25, internalOnly: true, publicOnly: false });

      const [path] = onlyCall('get') as [string];
      const [base, query] = path.split('?');
      expect(base).toBe('/v1/dns/zones');
      const params = new URLSearchParams(query);
      expect(Object.fromEntries(params)).toEqual({
        page: '2',
        limit: '25',
        internalOnly: 'true',
        publicOnly: 'false',
      });
    });

    it('updateZone puts only ttl and description under the encoded zone name', async () => {
      await service.updateZone({ name: 'zone/a', ttl: 120, description: 'new' });

      expect(onlyCall('put')).toEqual(['/v1/dns/zones/zone%2Fa', { ttl: 120, description: 'new' }]);
    });

    it('deleteZone deletes the zone by its encoded name', async () => {
      await service.deleteZone('zone a');

      expect(onlyCall('delete')).toEqual(['/v1/dns/zones/zone%20a']);
    });
  });

  describe('records', () => {
    it('addRecord posts the record wrapped in the record field', async () => {
      await service.addRecord({ zoneName: 'zone/a', record: oldRecord });

      expect(onlyCall('post')).toEqual(['/v1/dns/zones/zone%2Fa/records', { record: oldRecord }]);
    });

    it('listRecords sends the type filter as a query parameter', async () => {
      await service.listRecords({ zoneName: 'zone-a', type: 'TXT' });

      expect(onlyCall('get')).toEqual(['/v1/dns/zones/zone-a/records?type=TXT']);
    });

    it('listRecords sends no query without a type filter', async () => {
      await service.listRecords({ zoneName: 'zone a' });

      expect(onlyCall('get')).toEqual(['/v1/dns/zones/zone%20a/records']);
    });

    it('updateRecord puts the old and the new record', async () => {
      await service.updateRecord({ zoneName: 'zone-a', oldRecord, newRecord });

      expect(onlyCall('put')).toEqual(['/v1/dns/zones/zone-a/records', { oldRecord, newRecord }]);
    });

    it('deleteRecord deletes by zone, type and encoded record name', async () => {
      await service.deleteRecord({ zoneName: 'zone/a', type: 'CNAME', name: 'www a' });

      expect(onlyCall('delete')).toEqual(['/v1/dns/zones/zone%2Fa/records/CNAME/www%20a']);
    });
  });

  describe('dnssec', () => {
    it('signZone posts an empty body to the zone sign path', async () => {
      await service.signZone('zone/a');

      expect(onlyCall('post')).toEqual(['/v1/dns/zones/zone%2Fa/sign', {}]);
    });

    it('getDNSSECStatus gets the zone dnssec path', async () => {
      await service.getDNSSECStatus('zone a');

      expect(onlyCall('get')).toEqual(['/v1/dns/zones/zone%20a/dnssec']);
    });
  });

  describe('resolution', () => {
    it('resolve posts the query to /v1/dns/resolve', async () => {
      const request = { fqdn: 'svc.zone-a', type: 'AAAA' as const };
      await service.resolve(request);

      expect(onlyCall('post')).toEqual(['/v1/dns/resolve', request]);
    });

    it('register posts the hostname and address to /v1/dns/register', async () => {
      const request = { fqdn: 'svc.zone-a', ip: 'ip-1' };
      await service.register(request);

      expect(onlyCall('post')).toEqual(['/v1/dns/register', request]);
    });
  });

  describe('errors', () => {
    const cases: Array<[string, Verb, (s: DNSService) => Promise<unknown>]> = [
      ['createZone', 'post', (s) => s.createZone({ name: 'zone-a' })],
      ['getZone', 'get', (s) => s.getZone('zone-a')],
      ['listZones', 'get', (s) => s.listZones()],
      ['updateZone', 'put', (s) => s.updateZone({ name: 'zone-a' })],
      ['deleteZone', 'delete', (s) => s.deleteZone('zone-a')],
      ['addRecord', 'post', (s) => s.addRecord({ zoneName: 'zone-a', record: oldRecord })],
      ['listRecords', 'get', (s) => s.listRecords({ zoneName: 'zone-a' })],
      ['updateRecord', 'put', (s) => s.updateRecord({ zoneName: 'zone-a', oldRecord, newRecord })],
      ['deleteRecord', 'delete', (s) => s.deleteRecord({ zoneName: 'zone-a', type: 'A', name: 'svc' })],
      ['signZone', 'post', (s) => s.signZone('zone-a')],
      ['getDNSSECStatus', 'get', (s) => s.getDNSSECStatus('zone-a')],
      ['resolve', 'post', (s) => s.resolve({ fqdn: 'svc.zone-a', type: 'A' })],
      ['register', 'post', (s) => s.register({ fqdn: 'svc.zone-a', ip: 'ip-1' })],
    ];

    it.each(cases)('%s returns the transport error response unchanged', async (_name, verb, call) => {
      const failure = { success: false, error: { code: 'NOT_FOUND', message: 'no such zone' } };
      vi.mocked(mockClient[verb]).mockResolvedValue(failure);

      await expect(call(service)).resolves.toBe(failure);
    });

    it.each(cases)('%s rejects when the transport rejects', async (_name, verb, call) => {
      vi.mocked(mockClient[verb]).mockRejectedValue(new Error('transport down'));

      await expect(call(service)).rejects.toThrow('transport down');
    });
  });
});
