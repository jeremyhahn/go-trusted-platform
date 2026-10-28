/**
 * DNS Service Types
 *
 * Types for DNS zone and record management operations.
 * Based on pkg/api/grpc/proto/platform_dns.proto
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * DNS record type
 */
export type RecordType =
  | 'UNSPECIFIED'
  | 'A'
  | 'AAAA'
  | 'CNAME'
  | 'MX'
  | 'NS'
  | 'TXT'
  | 'SRV'
  | 'SOA'
  | 'CAA'
  | 'TLSA'
  | 'DNSKEY'
  | 'DS'
  | 'RRSIG'
  | 'NSEC'
  | 'NSEC3'
  | 'NSEC3PARAM';

/** Protobuf enum name of a record type (platform.v1.RecordType). */
export type RecordTypeProtoName = `RECORD_TYPE_${RecordType}`;

/**
 * Protobuf enum name of every record type. The REST decoder is protojson,
 * which accepts only the full enum name: a short name such as 'A' is
 * discarded, the type arrives unspecified and the record is refused.
 */
export const RECORD_TYPE_PROTO_NAMES: Readonly<Record<RecordType, RecordTypeProtoName>> = {
  UNSPECIFIED: 'RECORD_TYPE_UNSPECIFIED',
  A: 'RECORD_TYPE_A',
  AAAA: 'RECORD_TYPE_AAAA',
  CNAME: 'RECORD_TYPE_CNAME',
  MX: 'RECORD_TYPE_MX',
  NS: 'RECORD_TYPE_NS',
  TXT: 'RECORD_TYPE_TXT',
  SRV: 'RECORD_TYPE_SRV',
  SOA: 'RECORD_TYPE_SOA',
  CAA: 'RECORD_TYPE_CAA',
  TLSA: 'RECORD_TYPE_TLSA',
  DNSKEY: 'RECORD_TYPE_DNSKEY',
  DS: 'RECORD_TYPE_DS',
  RRSIG: 'RECORD_TYPE_RRSIG',
  NSEC: 'RECORD_TYPE_NSEC',
  NSEC3: 'RECORD_TYPE_NSEC3',
  NSEC3PARAM: 'RECORD_TYPE_NSEC3PARAM',
};

// =============================================================================
// Record Types
// =============================================================================

/**
 * SOA record
 */
export interface SOARecord {
  /** Name */
  name: string;
  /** Primary name server */
  mname: string;
  /** Admin email */
  rname: string;
  /** Serial number */
  serial: number;
  /** Refresh interval */
  refresh: number;
  /** Retry interval */
  retry: number;
  /** Expire time */
  expire: number;
  /** Minimum TTL */
  minimumTtl: number;
  /** TTL */
  ttl: number;
}

/**
 * A record
 */
export interface ARecord {
  /** Name */
  name: string;
  /** IPv4 address */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * AAAA record
 */
export interface AAAARecord {
  /** Name */
  name: string;
  /** IPv6 address */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * CNAME record
 */
export interface CNAMERecord {
  /** Name */
  name: string;
  /** Canonical name */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * MX record
 */
export interface MXRecord {
  /** Name */
  name: string;
  /** Mail server */
  value: string;
  /** Priority */
  priority: number;
  /** TTL */
  ttl: number;
}

/**
 * NS record
 */
export interface NSRecord {
  /** Name */
  name: string;
  /** Name server */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * TXT record
 */
export interface TXTRecord {
  /** Name */
  name: string;
  /** Text value */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * SRV record
 */
export interface SRVRecord {
  /** Name */
  name: string;
  /** Target */
  target: string;
  /** Port */
  port: number;
  /** Priority */
  priority: number;
  /** Weight */
  weight: number;
  /** TTL */
  ttl: number;
}

/**
 * CAA record
 */
export interface CAARecord {
  /** Name */
  name: string;
  /** Flags */
  flags: number;
  /** Tag */
  tag: string;
  /** Value */
  value: string;
  /** TTL */
  ttl: number;
}

/**
 * TLSA record (DANE)
 */
export interface TLSARecord {
  /** Name */
  name: string;
  /** Usage */
  usage: number;
  /** Selector */
  selector: number;
  /** Matching type */
  matchingType: number;
  /** Certificate data */
  data: string;
  /** TTL */
  ttl: number;
}

/**
 * DNSKEY record
 */
export interface DNSKEYRecord {
  /** Name */
  name: string;
  /** Flags */
  flags: number;
  /** Protocol */
  protocol: number;
  /** Algorithm */
  algorithm: number;
  /** Public key */
  key: string;
  /** TTL */
  ttl: number;
}

/**
 * DS record
 */
export interface DSRecord {
  /** Name */
  name: string;
  /** Key tag */
  keyTag: number;
  /** Algorithm */
  algorithm: number;
  /** Digest type */
  digestType: number;
  /** Digest */
  digest: string;
  /** TTL */
  ttl: number;
}

/**
 * RRSIG record
 */
export interface RRSIGRecord {
  /** Owner of the signed RRset; empty means the zone apex */
  name?: string;
  /** Type covered */
  typeCovered: string;
  /** Algorithm */
  algorithm: number;
  /** Labels */
  labels: number;
  /** Original TTL */
  originalTtl: number;
  /** Expiration */
  expiration: string;
  /** Inception */
  inception: string;
  /** Key tag */
  keyTag: number;
  /** Signer name */
  signerName: string;
  /** Signature */
  signature: string;
}

/**
 * NSEC record
 */
export interface NSECRecord {
  /** Name */
  name: string;
  /** Next domain */
  nextDomain: string;
  /** Type bitmap */
  typeBitmap: number[];
  /** TTL */
  ttl: number;
}

/**
 * NSEC3 record
 */
export interface NSEC3Record {
  /** Name */
  name: string;
  /** Algorithm */
  algorithm: number;
  /** Flags */
  flags: number;
  /** Iterations */
  iterations: number;
  /** Salt */
  salt: string;
  /** Next hashed */
  nextHashed: string;
  /** Type bitmap */
  typeBitmap: number[];
  /** TTL */
  ttl: number;
}

/**
 * NSEC3PARAM record
 */
export interface NSEC3PARAMRecord {
  /** Name */
  name: string;
  /** Algorithm */
  algorithm: number;
  /** Flags */
  flags: number;
  /** Iterations */
  iterations: number;
  /** Salt */
  salt: string;
  /** TTL */
  ttl: number;
}

/**
 * Record set
 */
export interface RecordSet {
  /** SOA record */
  soa?: SOARecord;
  /** A records */
  aRecords?: ARecord[];
  /** AAAA records */
  aaaaRecords?: AAAARecord[];
  /** CNAME records */
  cnameRecords?: CNAMERecord[];
  /** MX records */
  mxRecords?: MXRecord[];
  /** NS records */
  nsRecords?: NSRecord[];
  /** TXT records */
  txtRecords?: TXTRecord[];
  /** SRV records */
  srvRecords?: SRVRecord[];
  /** CAA records */
  caaRecords?: CAARecord[];
  /** TLSA records */
  tlsaRecords?: TLSARecord[];
  /** DNSKEY records */
  dnskeyRecords?: DNSKEYRecord[];
  /** DS records */
  dsRecords?: DSRecord[];
  /** RRSIG records */
  rrsigRecords?: RRSIGRecord[];
  /** NSEC records */
  nsecRecords?: NSECRecord[];
  /** NSEC3 records */
  nsec3Records?: NSEC3Record[];
  /** NSEC3PARAM records */
  nsec3paramRecords?: NSEC3PARAMRecord[];
}

/**
 * Generic record wrapper
 */
export interface DNSRecord {
  /** Record type */
  type: RecordType;
  /** A record */
  a?: ARecord;
  /** AAAA record */
  aaaa?: AAAARecord;
  /** CNAME record */
  cname?: CNAMERecord;
  /** MX record */
  mx?: MXRecord;
  /** NS record */
  ns?: NSRecord;
  /** TXT record */
  txt?: TXTRecord;
  /** SRV record */
  srv?: SRVRecord;
  /** CAA record */
  caa?: CAARecord;
  /** TLSA record */
  tlsa?: TLSARecord;
}

// =============================================================================
// Data Types
// =============================================================================

/**
 * DNS zone
 */
export interface Zone {
  /** Zone ID */
  id: number;
  /** Zone name */
  name: string;
  /** TTL */
  ttl: number;
  /** Description */
  description?: string;
  /** Internal zone */
  internal: boolean;
  /** Records */
  records?: RecordSet;
}

/**
 * DNSSEC status
 */
export interface DNSSECStatus {
  /** Whether enabled */
  enabled: boolean;
  /** Zone signed */
  zoneSigned: boolean;
  /** DNSKEY records */
  keys?: DNSKEYRecord[];
  /** DS records */
  dsRecords?: DSRecord[];
  /** Algorithm */
  algorithm?: string;
  /** Key size */
  keySize?: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create zone request
 */
export interface CreateZoneRequest {
  /** Zone name */
  name: string;
  /** TTL */
  ttl?: number;
  /** Description */
  description?: string;
  /** Internal zone */
  internal?: boolean;
  /** SOA record */
  soa?: SOARecord;
  /** NS records */
  nsRecords?: NSRecord[];
}

/**
 * Get zone request
 */
export interface GetZoneRequest {
  /** Zone name */
  name: string;
}

/**
 * Update zone request
 */
export interface UpdateZoneRequest {
  /** Zone name */
  name: string;
  /** Updated TTL */
  ttl?: number;
  /** Updated description */
  description?: string;
}

/**
 * Delete zone request
 */
export interface DeleteZoneRequest {
  /** Zone name */
  name: string;
}

/**
 * List zones request
 */
export interface ListZonesRequest {
  /** Internal only */
  internalOnly?: boolean;
  /** Public only */
  publicOnly?: boolean;
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
}

/**
 * Add record request
 */
export interface AddRecordRequest {
  /** Zone name */
  zoneName: string;
  /** Record */
  record: DNSRecord;
}

/**
 * Delete record request
 */
export interface DeleteRecordRequest {
  /** Zone name */
  zoneName: string;
  /** Record type */
  type: RecordType;
  /** Record name */
  name: string;
}

/**
 * Update record request
 */
export interface UpdateRecordRequest {
  /** Zone name */
  zoneName: string;
  /** Old record */
  oldRecord: DNSRecord;
  /** New record */
  newRecord: DNSRecord;
}

/**
 * List records request
 */
export interface ListRecordsRequest {
  /** Zone name */
  zoneName: string;
  /** Record type filter */
  type?: RecordType;
}

/**
 * Sign zone request
 */
export interface SignZoneRequest {
  /** Zone name */
  zoneName: string;
}

/**
 * Get DNSSEC status request
 */
export interface GetDNSSECStatusRequest {
  /** Zone name */
  zoneName: string;
}

/**
 * Resolve request
 */
export interface ResolveRequest {
  /** FQDN */
  fqdn: string;
  /** Record type */
  type: RecordType;
}

/**
 * Register request
 */
export interface RegisterRequest {
  /** FQDN */
  fqdn: string;
  /** IP address */
  ip: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface DNSStatus {
  /** Whether succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Pagination response
 */
export interface DNSPaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}

/**
 * Create zone response
 */
export interface CreateZoneResponse {
  /** Operation status */
  status: DNSStatus;
  /** Created zone */
  zone?: Zone;
}

/**
 * Get zone response
 */
export interface GetZoneResponse {
  /** Zone */
  zone: Zone;
}

/**
 * Update zone response
 */
export interface UpdateZoneResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}

/**
 * Delete zone response
 */
export interface DeleteZoneResponse {
  /** Operation status */
  status: DNSStatus;
}

/**
 * List zones response
 */
export interface ListZonesResponse {
  /** Zones */
  zones: Zone[];
  /** Pagination info */
  pagination?: DNSPaginationResponse;
}

/**
 * Add record response
 */
export interface AddRecordResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}

/**
 * Delete record response
 */
export interface DeleteRecordResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}

/**
 * Update record response
 */
export interface UpdateRecordResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}

/**
 * List records response
 */
export interface ListRecordsResponse {
  /** Records */
  records: DNSRecord[];
}

/**
 * Sign zone response
 */
export interface SignZoneResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}

/**
 * Get DNSSEC status response
 */
export interface GetDNSSECStatusResponse {
  /** DNSSEC status */
  status: DNSSECStatus;
}

/**
 * Resolve response
 */
export interface ResolveResponse {
  /** Records */
  records: DNSRecord[];
  /** Authoritative */
  authoritative: boolean;
}

/**
 * Register response
 */
export interface RegisterResponse {
  /** Operation status */
  status: DNSStatus;
  /** Updated zone */
  zone?: Zone;
}
