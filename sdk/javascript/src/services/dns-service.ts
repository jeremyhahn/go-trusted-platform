/**
 * DNS Service
 *
 * Provides operations for DNS zone and record management.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateZoneRequest,
  CreateZoneResponse,
  GetZoneResponse,
  UpdateZoneRequest,
  UpdateZoneResponse,
  DeleteZoneResponse,
  ListZonesRequest,
  ListZonesResponse,
  AddRecordRequest,
  AddRecordResponse,
  DeleteRecordRequest,
  DeleteRecordResponse,
  UpdateRecordRequest,
  UpdateRecordResponse,
  ListRecordsRequest,
  ListRecordsResponse,
  SignZoneResponse,
  GetDNSSECStatusResponse,
  ResolveRequest,
  ResolveResponse,
  RegisterRequest,
  RegisterResponse,
  DNSRecord,
} from '../types/dns.js';
import { RECORD_TYPE_PROTO_NAMES } from '../types/dns.js';

/** A record as the REST body carries it: the type as its protobuf name. */
function toProtoRecord(record: DNSRecord) {
  return { ...record, type: RECORD_TYPE_PROTO_NAMES[record.type] };
}

/**
 * DNS Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a zone
 * const zone = await client.dns.createZone({
 *   name: 'example.com',
 *   ttl: 3600,
 * });
 *
 * // Add a record
 * await client.dns.addRecord({
 *   zoneName: 'example.com',
 *   record: {
 *     type: 'A',
 *     a: { name: 'www', value: '192.168.1.1', ttl: 300 }
 *   }
 * });
 *
 * // Enable DNSSEC
 * await client.dns.signZone('example.com');
 * ```
 */
export class DNSService extends BaseService {
  /**
   * Creates a new DNS service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/dns');
  }

  // =========================================================================
  // Zone Operations
  // =========================================================================

  /**
   * Create a DNS zone
   *
   * @param request - Zone creation request
   * @returns Created zone
   */
  async createZone(request: CreateZoneRequest): Promise<ApiResponse<CreateZoneResponse>> {
    return this.client.post<CreateZoneResponse>(this.buildUrl('/zones'), request);
  }

  /**
   * Get zone by name
   *
   * @param name - Zone name
   * @returns Zone information
   */
  async getZone(name: string): Promise<ApiResponse<GetZoneResponse>> {
    return this.client.get<GetZoneResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(name)}`)
    );
  }

  /**
   * List zones
   *
   * @param request - List request
   * @returns List of zones
   */
  async listZones(request?: ListZonesRequest): Promise<ApiResponse<ListZonesResponse>> {
    return this.client.get<ListZonesResponse>(this.buildUrl('/zones', {
      page: request?.page,
      limit: request?.pageSize,
      filters: {
        internalOnly: request?.internalOnly?.toString(),
        publicOnly: request?.publicOnly?.toString(),
      },
    }));
  }

  /**
   * Update a zone
   *
   * @param request - Update request
   * @returns Updated zone
   */
  async updateZone(request: UpdateZoneRequest): Promise<ApiResponse<UpdateZoneResponse>> {
    return this.client.put<UpdateZoneResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(request.name)}`),
      { ttl: request.ttl, description: request.description }
    );
  }

  /**
   * Delete a zone
   *
   * @param name - Zone name
   * @returns Deletion result
   */
  async deleteZone(name: string): Promise<ApiResponse<DeleteZoneResponse>> {
    return this.client.delete<DeleteZoneResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(name)}`)
    );
  }

  // =========================================================================
  // Record Operations
  // =========================================================================

  /**
   * Add a record to a zone
   *
   * @param request - Record addition request
   * @returns Addition result
   */
  async addRecord(request: AddRecordRequest): Promise<ApiResponse<AddRecordResponse>> {
    return this.client.post<AddRecordResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(request.zoneName)}/records`),
      { record: toProtoRecord(request.record) }
    );
  }

  /**
   * List records in a zone
   *
   * @param request - List request
   * @returns List of records
   */
  async listRecords(request: ListRecordsRequest): Promise<ApiResponse<ListRecordsResponse>> {
    return this.client.get<ListRecordsResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(request.zoneName)}/records`, {
        filters: { type: request.type },
      })
    );
  }

  /**
   * Update a record
   *
   * @param request - Update request
   * @returns Updated zone
   */
  async updateRecord(request: UpdateRecordRequest): Promise<ApiResponse<UpdateRecordResponse>> {
    return this.client.put<UpdateRecordResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(request.zoneName)}/records`),
      { oldRecord: toProtoRecord(request.oldRecord), newRecord: toProtoRecord(request.newRecord) }
    );
  }

  /**
   * Delete a record from a zone
   *
   * @param request - Deletion request
   * @returns Deletion result
   */
  async deleteRecord(request: DeleteRecordRequest): Promise<ApiResponse<DeleteRecordResponse>> {
    return this.client.delete<DeleteRecordResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(request.zoneName)}/records/${request.type}/${this.encodePathSegment(request.name)}`)
    );
  }

  // =========================================================================
  // DNSSEC Operations
  // =========================================================================

  /**
   * Sign a zone with DNSSEC
   *
   * @param zoneName - Zone name
   * @returns Signing result
   */
  async signZone(zoneName: string): Promise<ApiResponse<SignZoneResponse>> {
    return this.client.post<SignZoneResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(zoneName)}/sign`),
      {}
    );
  }

  /**
   * Get DNSSEC status for a zone
   *
   * @param zoneName - Zone name
   * @returns DNSSEC status
   */
  async getDNSSECStatus(zoneName: string): Promise<ApiResponse<GetDNSSECStatusResponse>> {
    return this.client.get<GetDNSSECStatusResponse>(
      this.buildUrl(`/zones/${this.encodePathSegment(zoneName)}/dnssec`)
    );
  }

  // =========================================================================
  // Resolution Operations
  // =========================================================================

  /**
   * Resolve a DNS query
   *
   * @param request - Resolution request
   * @returns Resolution result
   */
  async resolve(request: ResolveRequest): Promise<ApiResponse<ResolveResponse>> {
    return this.client.post<ResolveResponse>(this.buildUrl('/resolve'), request);
  }

  /**
   * Register a hostname with IP
   *
   * @param request - Registration request
   * @returns Registration result
   */
  async register(request: RegisterRequest): Promise<ApiResponse<RegisterResponse>> {
    return this.client.post<RegisterResponse>(this.buildUrl('/register'), request);
  }
}
