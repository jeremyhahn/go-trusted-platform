import type { RecordType } from "trusted-platform-sdk";

/** The SDK's RecordType union, spelled out once for the runtime guard. */
const RECORD_TYPES = [
  "UNSPECIFIED", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SOA", "CAA",
  "TLSA", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
] as const satisfies readonly RecordType[];

/** UnsupportedRecordTypeError names a record type the SDK contract has no member for (e.g. PTR). */
export class UnsupportedRecordTypeError extends Error {
  readonly recordType: string;
  constructor(recordType: string) {
    super(`record type ${recordType} is not in the DNS SDK contract`);
    this.name = "UnsupportedRecordTypeError";
    this.recordType = recordType;
  }
}

/** isRecordType narrows a string to the SDK RecordType union. */
export function isRecordType(value: string): value is RecordType {
  return (RECORD_TYPES as readonly string[]).includes(value);
}

/** toRecordType converts a UI record-type string to the SDK union or throws a typed error. */
export function toRecordType(value: string): RecordType {
  if (!isRecordType(value)) throw new UnsupportedRecordTypeError(value);
  return value;
}
