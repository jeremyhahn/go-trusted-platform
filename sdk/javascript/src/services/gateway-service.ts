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
  GatewaySnapshot,
  ListGatewayStateResponse,
  GetNAT64StatusResponse,
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
  // Telemetry snapshots (#594)
  // =========================================================================

  /**
   * List the telemetry snapshot of every gateway that has reported to this
   * control plane, newest report first.
   *
   * This is the control plane's fleet read: it returns what each gatewayd
   * reported, whether or not this node runs a gateway itself.
   *
   * @returns Every reported gateway's snapshot
   */
  async listState(): Promise<ApiResponse<ListGatewayStateResponse>> {
    return this.client.get<ListGatewayStateResponse>(this.buildUrl('/state'));
  }

  /**
   * Get one gateway's telemetry snapshot: BGP sessions with their BFD state
   * and prefix counters, tunnels, uplink policy routes, the host filter, NAT,
   * the base OVS pipeline and every service's active/healthy state.
   *
   * A section the gateway does not run is absent from the snapshot rather
   * than present and empty.
   *
   * @param gatewayId - The reporting gateway's id
   * @returns That gateway's snapshot
   */
  async getState(gatewayId: string): Promise<ApiResponse<GatewaySnapshot>> {
    return this.client.get<GatewaySnapshot>(this.buildUrl(`/state/${encodeURIComponent(gatewayId)}`));
  }

  /**
   * Forget a gateway's cached state. Used when a gateway is decommissioned;
   * a live gateway re-reports on its next telemetry tick.
   *
   * @param gatewayId - The reporting gateway's id
   */
  async deleteState(gatewayId: string): Promise<ApiResponse<void>> {
    return this.client.delete(this.buildUrl(`/state/${encodeURIComponent(gatewayId)}`));
  }

  // =========================================================================
  // NAT64 Operations
  // =========================================================================

  /**
   * Get the NAT64 translator health.
   *
   * The gateway owns a Jool kernel instance and hands it the frames
   * addressed to the RFC 6052 translation prefix. What comes back is what
   * the kernel said: a started service whose instance has gone reports
   * `instance_present` false.
   *
   * The path is absolute rather than built from this service's `/v1/gateway`
   * basePath: the gateway feature is served by two REST routers — the web
   * service at `/api/v1/gateway/...` (status, mode, BGP, IPAM, state) and the
   * daemon transport at `/api/v1/sdn/gateway/...` — and NAT64 is registered
   * only on the daemon one (`pkg/api/rest/gateway_nat64_handlers.go`, and
   * docs/gateway/api.md §5a). Building it from basePath would request a path
   * nothing routes and return a 404 indistinguishable from a gateway with no
   * translator configured.
   *
   * @returns NAT64 translator status
   */
  async getNAT64Status(): Promise<ApiResponse<GetNAT64StatusResponse>> {
    return this.client.get<GetNAT64StatusResponse>('/v1/sdn/gateway/nat64/status');
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
    // DELETE /gateway/bgp/prefixes reads the CIDR from the `prefix` query
    // parameter (pkg/webservice/v1/rest/gateway/router.go withdrawPrefix).
    return this.client.delete<WithdrawPrefixResponse>(
      this.buildUrl(`/bgp/prefixes?prefix=${encodeURIComponent(request.prefix)}`)
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
    // POST /gateway/ipam/allocations decodes an AllocateIPRequest, pool id
    // included, from the body (router.go allocateIP).
    const body: AllocateIPRequest = { poolId: request.poolId };
    if (request.deviceId !== undefined) {
      body.deviceId = request.deviceId;
    }
    if (request.hostname !== undefined) {
      body.hostname = request.hostname;
    }
    return this.client.post<AllocateIPResponse>(this.buildUrl('/ipam/allocations'), body);
  }

  /**
   * Release an allocated IP
   *
   * @param request - Release request
   * @returns Release result
   */
  async releaseIP(request: ReleaseIPRequest): Promise<ApiResponse<ReleaseIPResponse>> {
    // DELETE /gateway/ipam/allocations reads the address from the `ip` query
    // parameter (router.go releaseIP).
    return this.client.delete<ReleaseIPResponse>(
      this.buildUrl(`/ipam/allocations?ip=${encodeURIComponent(request.ip)}`)
    );
  }

  /**
   * List IP allocations
   *
   * @param request - List request
   * @returns List of allocations
   */
  async listAllocations(request?: ListAllocationsRequest): Promise<ApiResponse<ListAllocationsResponse>> {
    // An empty poolId means every pool (ListAllocationsRequest), not a
    // filter. The router serves only GET /gateway/ipam/allocations, so the
    // pool goes in the `poolId` query parameter, never a /pools/{id} path.
    if (request?.poolId !== undefined && request.poolId !== '') {
      return this.client.get<ListAllocationsResponse>(
        this.buildUrl(`/ipam/allocations?poolId=${encodeURIComponent(request.poolId)}`)
      );
    }
    return this.client.get<ListAllocationsResponse>(this.buildUrl('/ipam/allocations'));
  }
}
