"use client";

/**
 * DNS records hook: ListRecords, served on
 * `GET /api/v1/dns/zones/{zone}/records?type=`
 * (pkg/webservice/v1/rest/dns/handlers.go ListRecords). It calls the SDK
 * DNSService from `useDNS()`, never a hand-written fetch. Responses name the
 * record type as RECORD_TYPE_<X>; the filter accepts the short name or the
 * protobuf name, anything else is refused with 400.
 */

import { useMemo } from "react";
import { useDNS, type DNSRecord, type RecordType } from "trusted-platform-sdk";

/** One display row for a DNS record. */
export interface DNSRecordRow {
  type: string;
  name: string;
  value: string;
  ttl: number;
}

const PROTO_PREFIX = "RECORD_TYPE_";

/** "RECORD_TYPE_A" or "A" to "A". */
export function shortRecordType(type: string): string {
  return type.startsWith(PROTO_PREFIX) ? type.slice(PROTO_PREFIX.length) : type;
}

/**
 * One row per record: the short type, and name/value/ttl of the first set
 * field among a, aaaa, cname, mx, ns, txt (an MX value is
 * `${priority} ${value}`); other types give name "", value "" and ttl 0.
 */
export function recordRow(record: DNSRecord): DNSRecordRow {
  const type = shortRecordType(String(record.type));
  const simple = record.a ?? record.aaaa ?? record.cname;
  if (simple) {
    return { type, name: simple.name ?? "", value: simple.value ?? "", ttl: simple.ttl ?? 0 };
  }
  if (record.mx) {
    const { name, value, priority, ttl } = record.mx;
    return { type, name: name ?? "", value: `${priority} ${value}`, ttl: ttl ?? 0 };
  }
  const rest = record.ns ?? record.txt;
  if (rest) {
    return { type, name: rest.name ?? "", value: rest.value ?? "", ttl: rest.ttl ?? 0 };
  }
  return { type, name: "", value: "", ttl: 0 };
}

/** The DNS record operations, through the SDK DNSService. */
export function useDNSRecords() {
  const dns = useDNS();
  return useMemo(
    () => ({
      listRecords: (zoneName: string, type?: RecordType) =>
        dns.listRecords(type ? { zoneName, type } : { zoneName }),
    }),
    [dns]
  );
}
