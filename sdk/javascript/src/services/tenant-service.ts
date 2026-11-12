/**
 * Tenant Service
 *
 * Provides operations for multi-tenant platform management: lifecycle, quotas, keys and barriers.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  InitTenantBarrierRequest,
  InitTenantBarrierResponse,
  UnsealTenantBarrierRequest,
  UnsealTenantBarrierResponse,
  SealTenantBarrierResponse,
  ListTenantsRequest,
  ListTenantsResponse,
  GetTenantResponse,
  GetTenantByNameResponse,
  CreateTenantRequest,
  CreateTenantResponse,
  UpdateTenantRequest,
  UpdateTenantResponse,
  DeleteTenantResponse,
  SuspendTenantResponse,
  ResumeTenantResponse,
  GetQuotasResponse,
  UpdateQuotasRequest,
  UpdateQuotasResponse,
  GetUsageResponse,
  CheckQuotaRequest,
  CheckQuotaResponse,
  SyncTenantsResponse,
  RotateTenantDEKRequest,
  RotateTenantDEKResponse,
  GetTenantDEKStatusResponse,
} from '../types/tenant.js';

/**
 * Tenant Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a tenant
 * const tenant = await client.tenant.createTenant({
 *   name: 'acme-corp',
 *   displayName: 'ACME Corporation',
 *   computeQuota: { maxVms: 50, maxContainers: 100 },
 * });
 *
 * // Check quota availability
 * const available = await client.tenant.checkQuota({
 *   tenantId: tenant.data.tenant.id,
 *   resource: 'vms',
 *   amount: 5,
 * });
 * ```
 */
export class TenantService extends BaseService {
  /**
   * Creates a new Tenant service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/tenants');
  }

  // =========================================================================
  // Tenant CRUD Operations
  // =========================================================================

  /**
   * Create a tenant
   *
   * @param request - Tenant creation request
   * @returns Created tenant
   */
  async createTenant(request: CreateTenantRequest): Promise<ApiResponse<CreateTenantResponse>> {
    return this.client.post<CreateTenantResponse>(this.buildUrl(''), request);
  }

  /**
   * Get tenant by ID
   *
   * @param tenantId - Tenant ID
   * @returns Tenant information
   */
  async getTenant(tenantId: string): Promise<ApiResponse<GetTenantResponse>> {
    return this.client.get<GetTenantResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}`)
    );
  }

  /**
   * Get tenant by name
   *
   * @param name - Tenant name
   * @returns Tenant information
   */
  async getTenantByName(name: string): Promise<ApiResponse<GetTenantByNameResponse>> {
    return this.client.get<GetTenantByNameResponse>(
      this.buildUrl(`/by-name/${this.encodePathSegment(name)}`)
    );
  }

  /**
   * List tenants
   *
   * @param request - List request with filters
   * @returns List of tenants
   */
  async listTenants(request?: ListTenantsRequest): Promise<ApiResponse<ListTenantsResponse>> {
    const filters: Record<string, string | undefined> = {};
    if (request?.selector?.matchLabels !== undefined) {
      Object.entries(request.selector.matchLabels).forEach(([k, v]) => {
        filters[`label_${k}`] = v;
      });
    }
    return this.client.get<ListTenantsResponse>(this.buildUrl('', {
      page: request?.offset !== undefined && request?.limit !== undefined
        ? Math.floor(request.offset / request.limit) + 1
        : undefined,
      limit: request?.limit,
      filters,
    }));
  }

  /**
   * Update a tenant
   *
   * @param request - Update request
   * @returns Updated tenant
   */
  async updateTenant(request: UpdateTenantRequest): Promise<ApiResponse<UpdateTenantResponse>> {
    return this.client.put<UpdateTenantResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}`),
      request
    );
  }

  /**
   * Delete a tenant
   *
   * @param tenantId - Tenant ID
   * @returns Deletion result
   */
  async deleteTenant(tenantId: string): Promise<ApiResponse<DeleteTenantResponse>> {
    return this.client.delete<DeleteTenantResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}`)
    );
  }

  // =========================================================================
  // Tenant State Operations
  // =========================================================================

  /**
   * Suspend a tenant
   *
   * @param tenantId - Tenant ID
   * @returns Suspension result
   */
  async suspendTenant(tenantId: string): Promise<ApiResponse<SuspendTenantResponse>> {
    return this.client.post<SuspendTenantResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/suspend`),
      {}
    );
  }

  /**
   * Resume a suspended tenant
   *
   * @param tenantId - Tenant ID
   * @returns Resume result
   */
  async resumeTenant(tenantId: string): Promise<ApiResponse<ResumeTenantResponse>> {
    return this.client.post<ResumeTenantResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/resume`),
      {}
    );
  }

  // =========================================================================
  // Quota Operations
  // =========================================================================

  /**
   * Get tenant quotas
   *
   * @param tenantId - Tenant ID
   * @returns Tenant quotas
   */
  async getQuotas(tenantId: string): Promise<ApiResponse<GetQuotasResponse>> {
    return this.client.get<GetQuotasResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/quotas`)
    );
  }

  /**
   * Update tenant quotas
   *
   * @param request - Update request
   * @returns Update result
   */
  async updateQuotas(request: UpdateQuotasRequest): Promise<ApiResponse<UpdateQuotasResponse>> {
    return this.client.put<UpdateQuotasResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}/quotas`),
      {
        compute: request.compute,
        network: request.network,
        storage: request.storage,
      }
    );
  }

  /**
   * Get tenant usage
   *
   * @param tenantId - Tenant ID
   * @returns Usage information
   */
  async getUsage(tenantId: string): Promise<ApiResponse<GetUsageResponse>> {
    return this.client.get<GetUsageResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/usage`)
    );
  }

  /**
   * Check quota availability
   *
   * @param request - Check request
   * @returns Availability result
   */
  async checkQuota(request: CheckQuotaRequest): Promise<ApiResponse<CheckQuotaResponse>> {
    return this.client.post<CheckQuotaResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}/quota-check`),
      { resource: request.resource, amount: request.amount }
    );
  }

  // =========================================================================
  // DEK (Data Encryption Key) Operations
  // =========================================================================

  /**
   * Rotate tenant DEK
   *
   * @param request - Rotation request
   * @returns Rotation result
   */
  async rotateDEK(request: RotateTenantDEKRequest): Promise<ApiResponse<RotateTenantDEKResponse>> {
    return this.client.post<RotateTenantDEKResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}/dek/rotate`),
      { background: request.background }
    );
  }

  /**
   * Get tenant DEK status
   *
   * @param tenantId - Tenant ID
   * @returns DEK status
   */
  async getDEKStatus(tenantId: string): Promise<ApiResponse<GetTenantDEKStatusResponse>> {
    return this.client.get<GetTenantDEKStatusResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/dek`)
    );
  }

  // =========================================================================
  // Admin Operations
  // =========================================================================

  /**
   * Sync tenants (admin operation)
   *
   * @returns Sync result
   */
  async syncTenants(): Promise<ApiResponse<SyncTenantsResponse>> {
    return this.client.post<SyncTenantsResponse>(this.buildUrl('/sync'), {});
  }

  // =========================================================================
  // Barrier Operations
  // =========================================================================

  /**
   * Initialise a tenant's barrier
   *
   * @param request - Init request (threshold and shares)
   * @returns Init result
   */
  async initBarrier(request: InitTenantBarrierRequest): Promise<ApiResponse<InitTenantBarrierResponse>> {
    return this.client.post<InitTenantBarrierResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}/barrier/init`),
      { threshold: request.threshold, shares: request.shares }
    );
  }

  /**
   * Unseal a tenant's barrier
   *
   * @param request - Unseal request (base64 key)
   * @returns Unseal result
   */
  async unsealBarrier(request: UnsealTenantBarrierRequest): Promise<ApiResponse<UnsealTenantBarrierResponse>> {
    return this.client.post<UnsealTenantBarrierResponse>(
      this.buildUrl(`/${this.encodePathSegment(request.tenantId)}/barrier/unseal`),
      { key: request.key }
    );
  }

  /**
   * Seal a tenant's barrier
   *
   * @param tenantId - Tenant ID
   * @returns Seal result
   */
  async sealBarrier(tenantId: string): Promise<ApiResponse<SealTenantBarrierResponse>> {
    return this.client.post<SealTenantBarrierResponse>(
      this.buildUrl(`/${this.encodePathSegment(tenantId)}/barrier/seal`),
      {}
    );
  }
}
