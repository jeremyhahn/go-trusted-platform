/**
 * Gateway Service
 *
 * Provides operations for multi-mode gateway management including BGP and IPAM.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  GetGatewayStatusResponse,
  SetGatewayModeRequest,
  SetGatewayModeResponse,
  GetBGPStatusResponse,
  ListBGPPeersResponse,
  AnnouncePrefixRequest,
  AnnouncePrefixResponse,
  WithdrawPrefixRequest,
  WithdrawPrefixResponse,
  ListAnnouncedPrefixesResponse,
  ListIPAMPoolsResponse,
  AllocateIPRequest,
  AllocateIPResponse,
  ReleaseIPRequest,
  ReleaseIPResponse,
  ListAllocationsRequest,
  ListAllocationsResponse,
} from '../types/gateway.js';

/**
 * Gateway Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get gateway status
 * const status = await client.gateway.getStatus();
 *
 * // Announce a prefix via BGP
 * await client.gateway.announcePrefix({
 *   prefix: '10.0.0.0/24',
 *   nextHop: '192.168.1.1',
 * });
 *
 * // Allocate IP from pool
 * const ip = await client.gateway.allocateIP({
 *   poolId: 'default-pool',
 *   hostname: 'server-001',
 * });
 * ```
 */
export class GatewayService extends BaseService {
  /**
   * Creates a new Gateway service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/gateway');
  }

  // =========================================================================
  // Gateway Status Operations
  // =========================================================================

  /**
   * Get gateway status
   *
   * @returns Gateway status
   */
  async getStatus(): Promise<ApiResponse<GetGatewayStatusResponse>> {
    return this.client.get<GetGatewayStatusResponse>(this.buildUrl('/status'));
  }

  /**
   * Set gateway mode
   *
   * @param request - Mode request
   * @returns Updated status
   */
  async setMode(request: SetGatewayModeRequest): Promise<ApiResponse<SetGatewayModeResponse>> {
    return this.client.post<SetGatewayModeResponse>(this.buildUrl('/mode'), request);
  }

  // =========================================================================
  // BGP Operations
  // =========================================================================

  /**
   * Get BGP status
   *
   * @returns BGP status
   */
  async getBGPStatus(): Promise<ApiResponse<GetBGPStatusResponse>> {
    return this.client.get<GetBGPStatusResponse>(this.buildUrl('/bgp/status'));
  }

  /**
   * List BGP peers
   *
   * @returns List of peers
   */
  async listBGPPeers(): Promise<ApiResponse<ListBGPPeersResponse>> {
    return this.client.get<ListBGPPeersResponse>(this.buildUrl('/bgp/peers'));
  }

  /**
   * Announce a prefix via BGP
   *
   * @param request - Announcement request
   * @returns Announcement result
   */
  async announcePrefix(request: AnnouncePrefixRequest): Promise<ApiResponse<AnnouncePrefixResponse>> {
    return this.client.post<AnnouncePrefixResponse>(this.buildUrl('/bgp/prefixes'), request);
  }

  /**
   * Withdraw a prefix from BGP
   *
   * @param request - Withdrawal request
   * @returns Withdrawal result
   */
  async withdrawPrefix(request: WithdrawPrefixRequest): Promise<ApiResponse<WithdrawPrefixResponse>> {
    return this.client.delete<WithdrawPrefixResponse>(
      this.buildUrl(`/bgp/prefixes/${this.encodePathSegment(request.prefix)}`)
    );
  }

  /**
   * List announced prefixes
   *
   * @returns List of announced prefixes
   */
  async listAnnouncedPrefixes(): Promise<ApiResponse<ListAnnouncedPrefixesResponse>> {
    return this.client.get<ListAnnouncedPrefixesResponse>(this.buildUrl('/bgp/prefixes'));
  }

  // =========================================================================
  // IPAM Operations
  // =========================================================================

  /**
   * List IPAM pools
   *
   * @returns List of pools
   */
  async listIPAMPools(): Promise<ApiResponse<ListIPAMPoolsResponse>> {
    return this.client.get<ListIPAMPoolsResponse>(this.buildUrl('/ipam/pools'));
  }

  /**
   * Allocate an IP from a pool
   *
   * @param request - Allocation request
   * @returns Allocated IP
   */
  async allocateIP(request: AllocateIPRequest): Promise<ApiResponse<AllocateIPResponse>> {
    return this.client.post<AllocateIPResponse>(
      this.buildUrl(`/ipam/pools/${this.encodePathSegment(request.poolId)}/allocate`),
      { deviceId: request.deviceId, hostname: request.hostname }
    );
  }

  /**
   * Release an allocated IP
   *
   * @param request - Release request
   * @returns Release result
   */
  async releaseIP(request: ReleaseIPRequest): Promise<ApiResponse<ReleaseIPResponse>> {
    return this.client.delete<ReleaseIPResponse>(
      this.buildUrl(`/ipam/allocations/${this.encodePathSegment(request.ip)}`)
    );
  }

  /**
   * List IP allocations
   *
   * @param request - List request
   * @returns List of allocations
   */
  async listAllocations(request?: ListAllocationsRequest): Promise<ApiResponse<ListAllocationsResponse>> {
    if (request?.poolId !== undefined) {
      return this.client.get<ListAllocationsResponse>(
        this.buildUrl(`/ipam/pools/${this.encodePathSegment(request.poolId)}/allocations`)
      );
    }
    return this.client.get<ListAllocationsResponse>(this.buildUrl('/ipam/allocations'));
  }
}
