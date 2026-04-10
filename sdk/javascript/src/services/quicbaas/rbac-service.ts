/**
 * QuicBaaS RBAC Service
 *
 * Provides operations for role-based access control including
 * role management, role assignments, and permission checking.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  QuicBaaSCreateRoleRequest,
  QuicBaaSGetRoleRequest,
  QuicBaaSUpdateRoleRequest,
  QuicBaaSDeleteRoleRequest,
  QuicBaaSListRolesRequest,
  QuicBaaSAssignRoleRequest,
  QuicBaaSRevokeRoleRequest,
  QuicBaaSCheckPermissionRequest,
  QuicBaaSCreateRoleResponse,
  QuicBaaSGetRoleResponse,
  QuicBaaSUpdateRoleResponse,
  QuicBaaSDeleteRoleResponse,
  QuicBaaSListRolesResponse,
  QuicBaaSAssignRoleResponse,
  QuicBaaSRevokeRoleResponse,
  QuicBaaSCheckPermissionResponse,
} from '../../types/quicbaas/security-part2.js';

/**
 * QuicBaaS RBAC Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a role
 * const role = await client.quicbaas.rbac.createRole({
 *   name: 'database-reader',
 *   description: 'Read-only access to databases',
 *   permissions: [
 *     {
 *       resourceType: 'DATABASE',
 *       resourcePattern: '*',
 *       actions: ['READ', 'LIST'],
 *     },
 *   ],
 * });
 *
 * // Assign role to a user
 * await client.quicbaas.rbac.assignRole({
 *   roleId: role.data.role?.roleId,
 *   principalId: 'user-123',
 *   principalType: 'USER',
 * });
 *
 * // Check permission
 * const allowed = await client.quicbaas.rbac.checkPermission({
 *   principalId: 'user-123',
 *   principalType: 'USER',
 *   resourceType: 'DATABASE',
 *   resourceId: 'production-db',
 *   action: 'READ',
 * });
 * ```
 */
export class RBACService extends BaseService {
  /**
   * Creates a new RBAC service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // Role Management
  // =========================================================================

  /**
   * Create a new role
   *
   * @param request - Role creation request
   * @returns Created role with metadata
   */
  async createRole(request: QuicBaaSCreateRoleRequest): Promise<ApiResponse<QuicBaaSCreateRoleResponse>> {
    return this.client.post<QuicBaaSCreateRoleResponse>(
      this.buildUrl('/rbac/roles'),
      request
    );
  }

  /**
   * Get role by ID
   *
   * @param roleId - Role identifier
   * @param options - Optional parameters
   * @returns Role with metadata and optional effective permissions
   */
  async getRole(
    roleId: string,
    options?: Omit<QuicBaaSGetRoleRequest, 'roleId'>
  ): Promise<ApiResponse<QuicBaaSGetRoleResponse>> {
    return this.client.get<QuicBaaSGetRoleResponse>(
      this.buildUrl(`/rbac/roles/${this.encodePathSegment(roleId)}`, {
        filters: {
          expandParents: options?.expandParents?.toString(),
          includeEffectivePermissions: options?.includeEffectivePermissions?.toString(),
        },
      })
    );
  }

  /**
   * Update an existing role
   *
   * @param request - Role update request
   * @returns Updated role with metadata
   */
  async updateRole(request: QuicBaaSUpdateRoleRequest): Promise<ApiResponse<QuicBaaSUpdateRoleResponse>> {
    return this.client.patch<QuicBaaSUpdateRoleResponse>(
      this.buildUrl(`/rbac/roles/${this.encodePathSegment(request.roleId)}`),
      {
        name: request.name,
        description: request.description,
        permissions: request.permissions,
        addPermissions: request.addPermissions,
        removePermissionIds: request.removePermissionIds,
        parentRoles: request.parentRoles,
      }
    );
  }

  /**
   * Delete a role
   *
   * @param request - Role deletion request
   * @returns Deletion result with removed assignment count
   */
  async deleteRole(request: QuicBaaSDeleteRoleRequest): Promise<ApiResponse<QuicBaaSDeleteRoleResponse>> {
    return this.client.delete<QuicBaaSDeleteRoleResponse>(
      this.buildUrl(`/rbac/roles/${this.encodePathSegment(request.roleId)}`, {
        filters: {
          force: request.force?.toString(),
        },
      })
    );
  }

  /**
   * List roles with optional filtering
   *
   * @param options - List options with filtering
   * @returns List of roles
   */
  async listRoles(options?: QuicBaaSListRolesRequest): Promise<ApiResponse<QuicBaaSListRolesResponse>> {
    return this.client.get<QuicBaaSListRolesResponse>(
      this.buildUrl('/rbac/roles', {
        limit: options?.limit,
        filters: {
          namePattern: options?.namePattern,
          includeSystem: options?.includeSystem?.toString(),
          cursor: options?.cursor,
        },
      })
    );
  }

  // =========================================================================
  // Role Assignments
  // =========================================================================

  /**
   * Assign a role to a principal
   *
   * @param request - Role assignment request
   * @returns Assignment result with metadata
   */
  async assignRole(request: QuicBaaSAssignRoleRequest): Promise<ApiResponse<QuicBaaSAssignRoleResponse>> {
    return this.client.post<QuicBaaSAssignRoleResponse>(
      this.buildUrl('/rbac/assignments'),
      request
    );
  }

  /**
   * Revoke a role from a principal
   *
   * @param request - Role revocation request
   * @returns Revocation result
   */
  async revokeRole(request: QuicBaaSRevokeRoleRequest): Promise<ApiResponse<QuicBaaSRevokeRoleResponse>> {
    return this.client.delete<QuicBaaSRevokeRoleResponse>(
      this.buildUrl('/rbac/assignments', {
        filters: {
          roleId: request.roleId,
          principalId: request.principalId,
          principalType: request.principalType,
          scope: request.scope,
        },
      })
    );
  }

  // =========================================================================
  // Permission Checking
  // =========================================================================

  /**
   * Check if a principal has a specific permission
   *
   * @param request - Permission check request
   * @returns Permission check result
   */
  async checkPermission(request: QuicBaaSCheckPermissionRequest): Promise<ApiResponse<QuicBaaSCheckPermissionResponse>> {
    return this.client.post<QuicBaaSCheckPermissionResponse>(
      this.buildUrl('/rbac/check'),
      request
    );
  }
}
