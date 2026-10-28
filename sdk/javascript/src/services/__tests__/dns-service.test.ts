/**
 * Unit tests for the DNS record bodies.
 *
 * `pkg/webservice/v1/rest/dns/handlers.go` decodes record bodies with
 * protojson, which accepts only the full enum name: a short record type such
 * as 'A' is discarded, the type arrives unspecified and the daemon refuses the
 * record as unsupported. These tests pin the protobuf name on the wire.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DNSService } from '../dns-service.js';
import type { ApiClient } from '../../client/api-client.js';
import type { DNSRecord, RecordType } from '../../types/dns.js';

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

const aRecord: DNSRecord = { type: 'A', a: { name: 'www', value: '192.0.2.10', ttl: 300 } };

describe('DNSService record bodies', () => {
  let service: DNSService;
  let mockClient: ApiClient;

  beforeEach(() => {
    mockClient = createMockApiClient();
    service = new DNSService(mockClient);
  });

  describe('addRecord', () => {
    it('sends the record type as its protobuf name', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.addRecord({ zoneName: 'example.com', record: aRecord });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/dns/zones/example.com/records', {
        record: { type: 'RECORD_TYPE_A', a: aRecord.a },
      });
    });

    it.each([
      ['UNSPECIFIED', 'RECORD_TYPE_UNSPECIFIED'],
      ['A', 'RECORD_TYPE_A'],
      ['AAAA', 'RECORD_TYPE_AAAA'],
      ['CNAME', 'RECORD_TYPE_CNAME'],
      ['MX', 'RECORD_TYPE_MX'],
      ['NS', 'RECORD_TYPE_NS'],
      ['TXT', 'RECORD_TYPE_TXT'],
      ['SRV', 'RECORD_TYPE_SRV'],
      ['SOA', 'RECORD_TYPE_SOA'],
      ['CAA', 'RECORD_TYPE_CAA'],
      ['TLSA', 'RECORD_TYPE_TLSA'],
      ['DNSKEY', 'RECORD_TYPE_DNSKEY'],
      ['DS', 'RECORD_TYPE_DS'],
      ['RRSIG', 'RECORD_TYPE_RRSIG'],
      ['NSEC', 'RECORD_TYPE_NSEC'],
      ['NSEC3', 'RECORD_TYPE_NSEC3'],
      ['NSEC3PARAM', 'RECORD_TYPE_NSEC3PARAM'],
    ] satisfies Array<[RecordType, string]>)('sends %s as its protobuf name %s', async (type, protoName) => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });

      await service.addRecord({ zoneName: 'example.com', record: { type } });

      expect(mockClient.post).toHaveBeenCalledWith('/v1/dns/zones/example.com/records', {
        record: { type: protoName },
      });
    });

    it('does not mutate the caller record', async () => {
      vi.mocked(mockClient.post).mockResolvedValue({ success: true, data: {} });
      const record: DNSRecord = { type: 'TXT', txt: { name: 'note', value: 'v=1', ttl: 60 } };

      await service.addRecord({ zoneName: 'example.com', record });

      expect(record.type).toBe('TXT');
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('400 Bad Request: unsupported record type');
      vi.mocked(mockClient.post).mockRejectedValue(failure);

      await expect(service.addRecord({ zoneName: 'example.com', record: aRecord })).rejects.toBe(failure);
    });
  });

  describe('updateRecord', () => {
    it('sends both record types as their protobuf names', async () => {
      vi.mocked(mockClient.put).mockResolvedValue({ success: true, data: {} });
      const newRecord: DNSRecord = { type: 'AAAA', aaaa: { name: 'www', value: '2001:db8::10', ttl: 300 } };

      await service.updateRecord({ zoneName: 'example.com', oldRecord: aRecord, newRecord });

      expect(mockClient.put).toHaveBeenCalledWith('/v1/dns/zones/example.com/records', {
        oldRecord: { type: 'RECORD_TYPE_A', a: aRecord.a },
        newRecord: { type: 'RECORD_TYPE_AAAA', aaaa: newRecord.aaaa },
      });
    });

    it('propagates a transport error unchanged', async () => {
      const failure = new Error('404 Not Found: record not found');
      vi.mocked(mockClient.put).mockRejectedValue(failure);

      await expect(
        service.updateRecord({ zoneName: 'example.com', oldRecord: aRecord, newRecord: aRecord })
      ).rejects.toBe(failure);
    });
  });
});
