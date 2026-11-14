/**
 * Overlay Service
 *
 * Provides operations for VXLAN and multi-host networking.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  ListVTEPsResponse,
  GetVTEPResponse,
  CreateVNIRequest,
  CreateVNIResponse,
  DeleteVNIResponse,
  ListVNIsResponse,
  ListTunnelsRequest,
  ListTunnelsResponse,
  GetTunnelStatsRequest,
  GetTunnelStatsResponse,
  ListRemoteMACsRequest,
  ListRemoteMACsResponse,
  ForgetMACRequest,
  ForgetMACResponse,
  GetOverlayStatusResponse,
} from '../types/overlay.js';

/**
 * Overlay Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Get overlay status
 * const status = await client.overlay.getStatus();
 *
 * // List VTEPs (VXLAN Tunnel Endpoints)
 * const vteps = await client.overlay.listVTEPs();
 *
 * // Create a VNI (Virtual Network Identifier)
 * const vni = await client.overlay.createVNI({
 *   config: { vni: 1000, vlan: 100, name: 'prod-network' }
 * });
 *
 * // List tunnels
 * const tunnels = await client.overlay.listTunnels({ vni: 1000 });
 * ```
 */
export class OverlayService extends BaseService {
  /**
   * Creates a new Overlay service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/overlay');
  }

  // =========================================================================
  // Status Operations
  // =========================================================================

  /**
   * Get overlay status
   *
   * @returns Overlay status
   */
  async getStatus(): Promise<ApiResponse<GetOverlayStatusResponse>> {
    return this.client.get<GetOverlayStatusResponse>(this.buildUrl('/status'));
  }

  // =========================================================================
  // VTEP Operations
  // =========================================================================

  /**
   * List VTEPs (VXLAN Tunnel Endpoints)
   *
   * @returns List of VTEPs
   */
  async listVTEPs(): Promise<ApiResponse<ListVTEPsResponse>> {
    return this.client.get<ListVTEPsResponse>(this.buildUrl('/vteps'));
  }

  /**
   * Get VTEP by node ID
   *
   * @param nodeId - Node ID
   * @returns VTEP information
   */
  async getVTEP(nodeId: string): Promise<ApiResponse<GetVTEPResponse>> {
    return this.client.get<GetVTEPResponse>(
      this.buildUrl(`/vteps/${this.encodePathSegment(nodeId)}`)
    );
  }

  // =========================================================================
  // VNI Operations
  // =========================================================================

  /**
   * Create a VNI (Virtual Network Identifier)
   *
   * @param request - VNI creation request
   * @returns Created VNI
   */
  async createVNI(request: CreateVNIRequest): Promise<ApiResponse<CreateVNIResponse>> {
    return this.client.post<CreateVNIResponse>(this.buildUrl('/vnis'), request);
  }

  /**
   * List VNIs
   *
   * @returns List of VNIs
   */
  async listVNIs(): Promise<ApiResponse<ListVNIsResponse>> {
    return this.client.get<ListVNIsResponse>(this.buildUrl('/vnis'));
  }

  /**
   * Delete a VNI
   *
   * @param vni - VNI number
   * @returns Deletion result
   */
  async deleteVNI(vni: number): Promise<ApiResponse<DeleteVNIResponse>> {
    return this.client.delete<DeleteVNIResponse>(this.buildUrl(`/vnis/${vni}`));
  }

  // =========================================================================
  // Tunnel Operations
  // =========================================================================

  /**
   * List tunnels
   *
   * @param request - List request
   * @returns List of tunnels
   */
  async listTunnels(request?: ListTunnelsRequest): Promise<ApiResponse<ListTunnelsResponse>> {
    return this.client.get<ListTunnelsResponse>(this.buildUrl('/tunnels', {
      filters: { vni: request?.vni?.toString() },
    }));
  }

  /**
   * Get tunnel statistics
   *
   * @param request - Stats request
   * @returns Tunnel statistics
   */
  async getTunnelStats(request: GetTunnelStatsRequest): Promise<ApiResponse<GetTunnelStatsResponse>> {
    return this.client.get<GetTunnelStatsResponse>(
      this.buildUrl('/tunnels/stats', {
        filters: { remote_vtep: request.remoteVtep, vni: request.vni?.toString() },
      })
    );
  }

  // =========================================================================
  // Remote MAC Operations
  // =========================================================================

  /**
   * List remote MAC entries
   *
   * @param request - List request
   * @returns List of MAC entries
   */
  async listRemoteMACs(request?: ListRemoteMACsRequest): Promise<ApiResponse<ListRemoteMACsResponse>> {
    return this.client.get<ListRemoteMACsResponse>(this.buildUrl('/macs', {
      filters: { vni: request?.vni?.toString() },
    }));
  }

  /**
   * Forget (remove) a remote MAC entry
   *
   * @param request - Forget request
   * @returns Forget result
   */
  async forgetMAC(request: ForgetMACRequest): Promise<ApiResponse<ForgetMACResponse>> {
    return this.client.delete<ForgetMACResponse>(
      this.buildUrl('/macs', {
        filters: { mac: request.mac, vni: request.vni?.toString() },
      })
    );
  }
}
