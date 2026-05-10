/**
 * SDN (Software-Defined Networking) Service
 *
 * Provides operations for bridges, ports, flows, and VLANs.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateBridgeRequest,
  CreateBridgeResponse,
  DeleteBridgeResponse,
  GetBridgeResponse,
  ListBridgesRequest,
  ListBridgesResponse,
  AddPortRequest,
  AddPortResponse,
  DeletePortResponse,
  GetPortResponse,
  ListPortsRequest,
  ListPortsResponse,
  AddFlowRequest,
  AddFlowResponse,
  DeleteFlowResponse,
  ListFlowsRequest,
  ListFlowsResponse,
  FlushFlowsRequest,
  FlushFlowsResponse,
  CreateVLANRequest,
  CreateVLANResponse,
  DeleteVLANResponse,
  ListVLANsRequest,
  ListVLANsResponse,
  AuthenticatePortRequest,
  AuthenticatePortResponse,
  RevokePortAuthResponse,
  GetPortStatsResponse,
  GetFlowStatsResponse,
} from '../types/sdn.js';

/**
 * SDN Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a bridge
 * const bridge = await client.sdn.createBridge({
 *   config: { name: 'br0', type: 'OVS', stpEnabled: true }
 * });
 *
 * // Add a port
 * const port = await client.sdn.addPort({
 *   bridgeId: bridge.data.bridge.id,
 *   config: { name: 'eth0', type: 'PHYSICAL' }
 * });
 *
 * // Add a flow
 * await client.sdn.addFlow({
 *   config: {
 *     bridgeId: bridge.data.bridge.id,
 *     priority: 100,
 *     match: { inPort: port.data.port.id, vlanId: 100 },
 *     actions: [{ type: 'OUTPUT', port: 'CONTROLLER' }],
 *   }
 * });
 * ```
 */
export class SDNService extends BaseService {
  /**
   * Creates a new SDN service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/sdn');
  }

  // =========================================================================
  // Bridge Operations
  // =========================================================================

  /**
   * Create a bridge
   *
   * @param request - Bridge creation request
   * @returns Created bridge
   */
  async createBridge(request: CreateBridgeRequest): Promise<ApiResponse<CreateBridgeResponse>> {
    return this.client.post<CreateBridgeResponse>(this.buildUrl('/bridges'), request);
  }

  /**
   * Get bridge by ID
   *
   * @param id - Bridge ID
   * @returns Bridge information
   */
  async getBridge(id: string): Promise<ApiResponse<GetBridgeResponse>> {
    return this.client.get<GetBridgeResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * List bridges
   *
   * @param request - List request
   * @returns List of bridges
   */
  async listBridges(request?: ListBridgesRequest): Promise<ApiResponse<ListBridgesResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request?.selector?.matchLabels !== undefined) {
      Object.entries(request.selector.matchLabels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    return this.client.get<ListBridgesResponse>(this.buildUrl('/bridges', {
      page: request?.page,
      limit: request?.pageSize,
      filters,
    }));
  }

  /**
   * Delete a bridge
   *
   * @param id - Bridge ID
   * @param force - Force deletion
   * @returns Deletion result
   */
  async deleteBridge(id: string, force?: boolean): Promise<ApiResponse<DeleteBridgeResponse>> {
    return this.client.delete<DeleteBridgeResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(id)}`, {
        filters: { force: force?.toString() },
      })
    );
  }

  // =========================================================================
  // Port Operations
  // =========================================================================

  /**
   * Add a port to a bridge
   *
   * @param request - Port addition request
   * @returns Added port
   */
  async addPort(request: AddPortRequest): Promise<ApiResponse<AddPortResponse>> {
    return this.client.post<AddPortResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/ports`),
      { config: request.config }
    );
  }

  /**
   * Get port by ID
   *
   * @param bridgeId - Bridge ID
   * @param portId - Port ID
   * @returns Port information
   */
  async getPort(bridgeId: string, portId: string): Promise<ApiResponse<GetPortResponse>> {
    return this.client.get<GetPortResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/ports/${this.encodePathSegment(portId)}`)
    );
  }

  /**
   * List ports on a bridge
   *
   * @param request - List request
   * @returns List of ports
   */
  async listPorts(request: ListPortsRequest): Promise<ApiResponse<ListPortsResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request.selector?.matchLabels !== undefined) {
      Object.entries(request.selector.matchLabels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    return this.client.get<ListPortsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/ports`, {
        page: request.page,
        limit: request.pageSize,
        filters,
      })
    );
  }

  /**
   * Delete a port
   *
   * @param bridgeId - Bridge ID
   * @param portId - Port ID
   * @returns Deletion result
   */
  async deletePort(bridgeId: string, portId: string): Promise<ApiResponse<DeletePortResponse>> {
    return this.client.delete<DeletePortResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/ports/${this.encodePathSegment(portId)}`)
    );
  }

  /**
   * Get port statistics
   *
   * @param bridgeId - Bridge ID
   * @param portId - Port ID
   * @returns Port statistics
   */
  async getPortStats(bridgeId: string, portId: string): Promise<ApiResponse<GetPortStatsResponse>> {
    return this.client.get<GetPortStatsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/ports/${this.encodePathSegment(portId)}/stats`)
    );
  }

  // =========================================================================
  // Port Authentication Operations
  // =========================================================================

  /**
   * Authenticate a port with certificate
   *
   * @param request - Authentication request
   * @returns Authentication result
   */
  async authenticatePort(request: AuthenticatePortRequest): Promise<ApiResponse<AuthenticatePortResponse>> {
    return this.client.post<AuthenticatePortResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/ports/${this.encodePathSegment(request.portId)}/auth`),
      { certificate: request.certificate, format: request.format }
    );
  }

  /**
   * Revoke port authentication
   *
   * @param bridgeId - Bridge ID
   * @param portId - Port ID
   * @returns Revocation result
   */
  async revokePortAuth(bridgeId: string, portId: string): Promise<ApiResponse<RevokePortAuthResponse>> {
    return this.client.delete<RevokePortAuthResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/ports/${this.encodePathSegment(portId)}/auth`)
    );
  }

  // =========================================================================
  // Flow Operations
  // =========================================================================

  /**
   * Add a flow
   *
   * @param request - Flow addition request
   * @returns Added flow
   */
  async addFlow(request: AddFlowRequest): Promise<ApiResponse<AddFlowResponse>> {
    return this.client.post<AddFlowResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.config.bridgeId)}/flows`),
      { config: request.config }
    );
  }

  /**
   * List flows on a bridge
   *
   * @param request - List request
   * @returns List of flows
   */
  async listFlows(request: ListFlowsRequest): Promise<ApiResponse<ListFlowsResponse>> {
    return this.client.get<ListFlowsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/flows`, {
        page: request.page,
        limit: request.pageSize,
        filters: { table: request.table },
      })
    );
  }

  /**
   * Delete a flow
   *
   * @param bridgeId - Bridge ID
   * @param flowId - Flow ID
   * @returns Deletion result
   */
  async deleteFlow(bridgeId: string, flowId: string): Promise<ApiResponse<DeleteFlowResponse>> {
    return this.client.delete<DeleteFlowResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/flows/${this.encodePathSegment(flowId)}`)
    );
  }

  /**
   * Flush flows from a bridge
   *
   * @param request - Flush request
   * @returns Flush result
   */
  async flushFlows(request: FlushFlowsRequest): Promise<ApiResponse<FlushFlowsResponse>> {
    return this.client.post<FlushFlowsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/flows/flush`),
      { table: request.table }
    );
  }

  /**
   * Get flow statistics
   *
   * @param bridgeId - Bridge ID
   * @param flowId - Flow ID
   * @returns Flow statistics
   */
  async getFlowStats(bridgeId: string, flowId: string): Promise<ApiResponse<GetFlowStatsResponse>> {
    return this.client.get<GetFlowStatsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/flows/${this.encodePathSegment(flowId)}/stats`)
    );
  }

  // =========================================================================
  // VLAN Operations
  // =========================================================================

  /**
   * Create a VLAN
   *
   * @param request - VLAN creation request
   * @returns Created VLAN
   */
  async createVLAN(request: CreateVLANRequest): Promise<ApiResponse<CreateVLANResponse>> {
    return this.client.post<CreateVLANResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.config.bridgeId)}/vlans`),
      { config: request.config }
    );
  }

  /**
   * List VLANs on a bridge
   *
   * @param request - List request
   * @returns List of VLANs
   */
  async listVLANs(request: ListVLANsRequest): Promise<ApiResponse<ListVLANsResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request.selector?.matchLabels !== undefined) {
      Object.entries(request.selector.matchLabels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    return this.client.get<ListVLANsResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(request.bridgeId)}/vlans`, {
        filters,
      })
    );
  }

  /**
   * Delete a VLAN
   *
   * @param bridgeId - Bridge ID
   * @param vlanId - VLAN ID
   * @returns Deletion result
   */
  async deleteVLAN(bridgeId: string, vlanId: number): Promise<ApiResponse<DeleteVLANResponse>> {
    return this.client.delete<DeleteVLANResponse>(
      this.buildUrl(`/bridges/${this.encodePathSegment(bridgeId)}/vlans/${vlanId}`)
    );
  }
}
