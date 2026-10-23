/**
 * VPN Service
 *
 * The remote-access VPN operator control plane: peer enrolment, session
 * status and tenant posture policies. It mirrors sdk/go/services/vpn over the
 * REST routes in docs/vpn/api.md §1.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  EnrolVPNPeerRequest,
  EnrolVPNPeerResponse,
  ListVPNPeersResponse,
  RevokeVPNPeerResponse,
  GetVPNStatusResponse,
  GetVPNPosturePolicyResponse,
  SetVPNPosturePolicyRequest,
  SetVPNPosturePolicyResponse,
  DeleteVPNPosturePolicyResponse,
  ListVPNPosturePoliciesResponse,
} from '../types/vpn.js';

/**
 * VPN Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Enrol a laptop for the management zone
 * await client.vpn.enrolPeer({ tenantId: 'acme', deviceId: 'laptop-1', zones: ['management'] });
 *
 * // Every gateway's sessions
 * const status = await client.vpn.getStatus();
 * ```
 */
export class VPNService extends BaseService {
  /**
   * Creates a new VPN service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/vpn');
  }

  // =========================================================================
  // Peer Operations
  // =========================================================================

  /**
   * Enrol a device as a VPN peer of a tenant, or replace the zones of its
   * enrolment. Re-enrolling keeps the first enrolment time.
   *
   * @param request - The tenant, device and zones
   * @returns The stored enrolment
   */
  async enrolPeer(request: EnrolVPNPeerRequest): Promise<ApiResponse<EnrolVPNPeerResponse>> {
    return this.client.post<EnrolVPNPeerResponse>(this.buildUrl('/peers'), {
      tenantId: request.tenantId,
      deviceId: request.deviceId,
      zones: request.zones ?? [],
    });
  }

  /**
   * List the enrolled peers of one tenant, or of every tenant
   *
   * @param tenantId - The tenant; empty or omitted lists every tenant
   * @returns The enrolled peers
   */
  async listPeers(tenantId?: string): Promise<ApiResponse<ListVPNPeersResponse>> {
    return this.client.get<ListVPNPeersResponse>(this.withQuery('/peers', 'tenant_id', tenantId));
  }

  /**
   * Revoke a peer's enrolment. The gateways revoke the device's leases when
   * the change reaches them.
   *
   * @param tenantId - The peer's tenant
   * @param deviceId - The peer's device
   */
  async revokePeer(
    tenantId: string,
    deviceId: string
  ): Promise<ApiResponse<RevokeVPNPeerResponse>> {
    return this.client.delete<RevokeVPNPeerResponse>(
      this.withQuery(`/peers/${this.encodePathSegment(deviceId)}`, 'tenant_id', tenantId)
    );
  }

  // =========================================================================
  // Session Status
  // =========================================================================

  /**
   * Get the VPN session state the gateways last reported
   *
   * @param gatewayId - One gateway; empty or omitted reports every gateway
   * @returns Each gateway's VPN status
   */
  async getStatus(gatewayId?: string): Promise<ApiResponse<GetVPNStatusResponse>> {
    return this.client.get<GetVPNStatusResponse>(
      this.withQuery('/status', 'gateway_id', gatewayId)
    );
  }

  // =========================================================================
  // Posture Policy Operations
  // =========================================================================

  /**
   * Get one tenant posture policy
   *
   * @param tenantId - The policy's tenant
   * @param name - The policy name
   * @returns The policy
   */
  async getPosturePolicy(
    tenantId: string,
    name: string
  ): Promise<ApiResponse<GetVPNPosturePolicyResponse>> {
    return this.client.get<GetVPNPosturePolicyResponse>(this.posturePolicyUrl(tenantId, name));
  }

  /**
   * Create or replace a tenant posture policy. A module that does not compile
   * as package vpn.posture is refused and nothing is stored.
   *
   * @param request - The tenant, name and Rego module
   * @returns The stored policy
   */
  async setPosturePolicy(
    request: SetVPNPosturePolicyRequest
  ): Promise<ApiResponse<SetVPNPosturePolicyResponse>> {
    return this.client.put<SetVPNPosturePolicyResponse>(
      this.buildUrl(`/posture-policies/${this.encodePathSegment(request.name)}`),
      { tenantId: request.tenantId, name: request.name, module: request.module }
    );
  }

  /**
   * Delete a tenant posture policy
   *
   * @param tenantId - The policy's tenant
   * @param name - The policy name
   */
  async deletePosturePolicy(
    tenantId: string,
    name: string
  ): Promise<ApiResponse<DeleteVPNPosturePolicyResponse>> {
    return this.client.delete<DeleteVPNPosturePolicyResponse>(
      this.posturePolicyUrl(tenantId, name)
    );
  }

  /**
   * List the posture policies of one tenant, or of every tenant
   *
   * @param tenantId - The tenant; empty or omitted lists every tenant
   * @returns The policies
   */
  async listPosturePolicies(
    tenantId?: string
  ): Promise<ApiResponse<ListVPNPosturePoliciesResponse>> {
    return this.client.get<ListVPNPosturePoliciesResponse>(
      this.withQuery('/posture-policies', 'tenant_id', tenantId)
    );
  }

  private posturePolicyUrl(tenantId: string, name: string): string {
    return this.withQuery(
      `/posture-policies/${this.encodePathSegment(name)}`,
      'tenant_id',
      tenantId
    );
  }

  /**
   * Builds a path under this service with one optional query parameter,
   * left off when the value is empty.
   */
  private withQuery(path: string, key: string, value?: string): string {
    const url = this.buildUrl(path);
    if (value === undefined || value.length === 0) {
      return url;
    }
    return `${url}?${new URLSearchParams({ [key]: value }).toString()}`;
  }
}
