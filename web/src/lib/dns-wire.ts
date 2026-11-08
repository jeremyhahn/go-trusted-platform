/**
 * Readers for the DNS REST routes' wire shape.
 *
 * The webservice answers every zone route with its gRPC DNSService response
 * message in the proto JSON mapping (#445, docs/dns/api-reference-rest.md):
 * each record type is its own camelCase list (`aRecords`, `mxRecords`, ...),
 * the zone id is a uint64 and so arrives as a decimal string, and an unset
 * message field (`records`, `soa`) arrives as `null`.
 */
import type { RecordSet, Zone } from 'trusted-platform-sdk';
import type { DNSRecord, DNSZone, DNSZoneDetail } from '@/types/infrastructure';

const defaultTTL = 3600;
const defaultRefresh = 3600;
const defaultRetry = 600;
const defaultExpire = 604800;

/**
 * Counts every record of a zone's RecordSet: each list contributes its
 * length and the SOA contributes one.
 */
export function countZoneRecords(records: RecordSet | null | undefined): number {
  if (!records) return 0;
  return Object.values(records).reduce<number>((count, value) => {
    if (Array.isArray(value)) return count + value.length;
    return value ? count + 1 : count;
  }, 0);
}

/**
 * Reads one zone of a ListZonesResponse as the zone table shows it. The proto
 * Zone carries no timestamps, so createdAt and updatedAt stay empty and the
 * table renders "—".
 */
export function readZone(zone: Zone): DNSZone {
  const soa = zone.records?.soa;
  return {
    id: String(zone.id),
    name: zone.name,
    type: zone.internal ? 'primary' : 'secondary',
    recordCount: countZoneRecords(zone.records),
    ttl: zone.ttl || defaultTTL,
    serial: soa?.serial || 0,
    refresh: soa?.refresh || defaultRefresh,
    retry: soa?.retry || defaultRetry,
    expire: soa?.expire || defaultExpire,
    createdAt: '',
    updatedAt: '',
  };
}

function record(
  name: string,
  type: DNSRecord['type'],
  value: string,
  ttl: number | undefined,
  extra?: Partial<DNSRecord>,
): DNSRecord {
  return { id: `${type}-${name}-${value}`, name, type, value, ttl: ttl ?? 0, ...extra };
}

/** Reads the zone of a GetZoneResponse as the zone detail page shows it. */
export function readZoneDetail(zone: Zone): DNSZoneDetail {
  const recordSet: RecordSet = zone.records ?? {};
  const nsRecords = recordSet.nsRecords ?? [];
  const soa = recordSet.soa ?? undefined;

  const records: DNSRecord[] = [
    ...(recordSet.aRecords ?? []).map((r) => record(r.name, 'A', r.value, r.ttl)),
    ...(recordSet.aaaaRecords ?? []).map((r) => record(r.name, 'AAAA', r.value, r.ttl)),
    ...(recordSet.cnameRecords ?? []).map((r) => record(r.name, 'CNAME', r.value, r.ttl)),
    ...(recordSet.mxRecords ?? []).map((r) =>
      record(r.name, 'MX', r.value, r.ttl, { priority: r.priority }),
    ),
    ...(recordSet.txtRecords ?? []).map((r) => record(r.name, 'TXT', r.value, r.ttl)),
    ...nsRecords.map((r) => record(r.name, 'NS', r.value, r.ttl)),
  ];
  if (soa) {
    records.push(record(soa.name, 'SOA', `${soa.mname} ${soa.rname} ${soa.serial}`, soa.ttl));
  }

  return {
    ...readZone(zone),
    type: 'primary',
    recordCount: records.length,
    ttl: zone.ttl,
    nameservers: nsRecords.map((ns) => ns.value),
    adminEmail: soa?.rname || `admin@${zone.name}`,
    records,
  };
}
