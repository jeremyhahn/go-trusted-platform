import { describe, expect, it } from 'vitest';
import type { GetZoneResponse, ListZonesResponse, Zone } from 'trusted-platform-sdk';
import { countZoneRecords, readZone, readZoneDetail } from './dns-wire';

// A GetZoneResponse payload as the webservice answers it: protojson with
// EmitUnpopulated, so the uint64 id is a string and every list is present.
const getZoneWire = `{
  "zone": {
    "id": "7",
    "name": "example.com.",
    "ttl": 300,
    "description": "",
    "internal": true,
    "records": {
      "soa": {"name": "example.com.", "mname": "ns1.example.com.", "rname": "hostmaster.example.com.",
              "serial": 2026102701, "refresh": 7200, "retry": 900, "expire": 1209600, "minimumTtl": 60, "ttl": 300},
      "aRecords": [{"name": "www", "value": "192.0.2.10", "ttl": 300}],
      "aaaaRecords": [{"name": "www", "value": "2001:db8::10", "ttl": 300}],
      "cnameRecords": [{"name": "api", "value": "www.example.com.", "ttl": 60}],
      "mxRecords": [{"name": "@", "value": "mail.example.com.", "priority": 10, "ttl": 300}],
      "nsRecords": [{"name": "@", "value": "ns1.example.com.", "ttl": 300}],
      "txtRecords": [{"name": "@", "value": "v=spf1 -all", "ttl": 300}],
      "srvRecords": [], "caaRecords": [], "tlsaRecords": [], "dnskeyRecords": [], "dsRecords": [],
      "rrsigRecords": [], "nsecRecords": [], "nsec3Records": [], "nsec3paramRecords": []
    }
  }
}`;

// A zone with no records, as protojson writes an unset message field.
const bareZoneWire = `{"id": "8", "name": "empty.test.", "ttl": 0, "description": "", "internal": false, "records": null}`;

function getZone(): Zone {
  return (JSON.parse(getZoneWire) as GetZoneResponse).zone;
}

describe('countZoneRecords', () => {
  it('counts every list entry and the SOA', () => {
    expect(countZoneRecords(getZone().records)).toBe(7);
  });

  it('counts a null record set as empty', () => {
    expect(countZoneRecords(null)).toBe(0);
    expect(countZoneRecords(undefined)).toBe(0);
  });
});

describe('readZone', () => {
  it('reads a ListZonesResponse zone into a table row', () => {
    const list = JSON.parse(`{"zones": [${JSON.stringify(getZone())}], "pagination": null}`) as ListZonesResponse;
    expect(list.zones.map(readZone)).toEqual([
      {
        id: '7',
        name: 'example.com.',
        type: 'primary',
        recordCount: 7,
        ttl: 300,
        serial: 2026102701,
        refresh: 7200,
        retry: 900,
        expire: 1209600,
        createdAt: '',
        updatedAt: '',
      },
    ]);
  });

  it('defaults the SOA timers of a zone with null records', () => {
    const row = readZone(JSON.parse(bareZoneWire) as Zone);
    expect(row).toMatchObject({
      id: '8',
      type: 'secondary',
      recordCount: 0,
      ttl: 3600,
      serial: 0,
      refresh: 3600,
      retry: 600,
      expire: 604800,
    });
  });
});

describe('readZoneDetail', () => {
  it('reads every camelCase record list of a GetZoneResponse', () => {
    const detail = readZoneDetail(getZone());
    expect(detail.records.map((r) => [r.type, r.name, r.value, r.ttl])).toEqual([
      ['A', 'www', '192.0.2.10', 300],
      ['AAAA', 'www', '2001:db8::10', 300],
      ['CNAME', 'api', 'www.example.com.', 60],
      ['MX', '@', 'mail.example.com.', 300],
      ['TXT', '@', 'v=spf1 -all', 300],
      ['NS', '@', 'ns1.example.com.', 300],
      ['SOA', 'example.com.', 'ns1.example.com. hostmaster.example.com. 2026102701', 300],
    ]);
    expect(detail.records.find((r) => r.type === 'MX')?.priority).toBe(10);
    expect(detail).toMatchObject({
      id: '7',
      type: 'primary',
      recordCount: 7,
      ttl: 300,
      serial: 2026102701,
      nameservers: ['ns1.example.com.'],
      adminEmail: 'hostmaster.example.com.',
      createdAt: '',
    });
  });

  it('reads a zone with null records as empty, with a derived admin email', () => {
    const detail = readZoneDetail(JSON.parse(bareZoneWire) as Zone);
    expect(detail.records).toEqual([]);
    expect(detail.nameservers).toEqual([]);
    expect(detail.recordCount).toBe(0);
    expect(detail.adminEmail).toBe('admin@empty.test.');
  });
});
