/**
 * IAM (Identity and Access Management) Service
 *
 * Provides operations for users, roles, groups, tenants, policies, and applications.
 */

import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  // User types
  CreateIAMUserRequest,
  ListIAMUsersRequest,
  UpdateIAMUserRequest,
  IAMUserResponse,
  ListIAMUsersResponse,
  DeleteIAMUserResponse,
  // Role types
  CreateIAMRoleRequest,
  ListIAMRolesRequest,
  UpdateIAMRoleRequest,
  AssignIAMRoleRequest,
  RevokeIAMRoleRequest,
  IAMRoleResponse,
  ListIAMRolesResponse,
  DeleteIAMRoleResponse,
  AssignIAMRoleResponse,
  RevokeIAMRoleResponse,
  // Group types
  CreateIAMGroupRequest,
  ListIAMGroupsRequest,
  UpdateIAMGroupRequest,
  AddGroupMemberRequest,
  RemoveGroupMemberRequest,
  IAMGroupResponse,
  ListIAMGroupsResponse,
  DeleteIAMGroupResponse,
  AddGroupMemberResponse,
  RemoveGroupMemberResponse,
  // Authentication types
  AuthenticateIAMRequest,
  AuthenticateIAMResponse,
  CheckIAMPermissionRequest,
  CheckIAMPermissionResponse,
  CreateIAMTokenRequest,
  CreateIAMTokenResponse,
  RevokeIAMTokenRequest,
  RevokeIAMTokenResponse,
  VerifyIAMTokenRequest,
  VerifyIAMTokenResponse,
  // Tenant types
  CreateIAMTenantRequest,
  ListIAMTenantsRequest,
  UpdateIAMTenantRequest,
  IAMTenantResponse,
  ListIAMTenantsResponse,
  DeleteIAMTenantResponse,
  // Policy types
  CreateIAMPolicyRequest,
  ListIAMPoliciesRequest,
  UpdateIAMPolicyRequest,
  ValidateIAMPolicyRequest,
  ValidateIAMPolicyResponse,
  TestIAMPolicyRequest,
  TestIAMPolicyResponse,
  IAMPolicyResponse,
  ListIAMPoliciesResponse,
  DeleteIAMPolicyResponse,
  // Application types
  RegisterIAMAppRequest,
  ListIAMAppsRequest,
  UpdateIAMAppRequest,
  RotateIAMAppSecretResponse,
  IAMAppResponse,
  ListIAMAppsResponse,
  DeleteIAMAppResponse,
} from '../types/iam.js';

/**
 * IAM Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a user
 * const user = await client.iam.createUser({
 *   tenantId: 'tenant-1',
 *   email: 'user@example.com',
 *   name: 'John Doe',
 *   roles: ['admin'],
 * });
 *
 * // Check permission
 * const permission = await client.iam.checkPermission({
 *   tenantId: 'tenant-1',
 *   subjectId: user.data.user.id,
 *   action: 'read',
 *   resource: '/api/v1/secrets/*',
 * });
 * ```
 */
export class IAMService extends BaseService {
  /**
   * Creates a new IAM service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/iam');
  }

  // =========================================================================
  // User Operations
  // =========================================================================

  /**
   * Create a user
   */
  async createUser(request: CreateIAMUserRequest): Promise<ApiResponse<IAMUserResponse>> {
    return this.client.post<IAMUserResponse>(this.buildUrl('/users'), request);
  }

  /**
   * Get user by ID
   */
  async getUser(tenantId: string, userId: string): Promise<ApiResponse<IAMUserResponse>> {
    return this.client.get<IAMUserResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/users/${this.encodePathSegment(userId)}`)
    );
  }

  /**
   * List users
   */
  async listUsers(request: ListIAMUsersRequest): Promise<ApiResponse<ListIAMUsersResponse>> {
    return this.client.get<ListIAMUsersResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/users`, {
        page: request.page,
        limit: request.pageSize,
        filters: {
          email: request.emailFilter,
          role: request.roleFilter,
          group: request.groupFilter,
        },
      })
    );
  }

  /**
   * Update a user
   */
  async updateUser(request: UpdateIAMUserRequest): Promise<ApiResponse<IAMUserResponse>> {
    return this.client.put<IAMUserResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/users/${this.encodePathSegment(request.userId)}`),
      request
    );
  }

  /**
   * Delete a user
   */
  async deleteUser(tenantId: string, userId: string): Promise<ApiResponse<DeleteIAMUserResponse>> {
    return this.client.delete<DeleteIAMUserResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/users/${this.encodePathSegment(userId)}`)
    );
  }

  // =========================================================================
  // Role Operations
  // =========================================================================

  /**
   * Create a role
   */
  async createRole(request: CreateIAMRoleRequest): Promise<ApiResponse<IAMRoleResponse>> {
    return this.client.post<IAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/roles`),
      request
    );
  }

  /**
   * Get role by ID
   */
  async getRole(tenantId: string, roleId: string): Promise<ApiResponse<IAMRoleResponse>> {
    return this.client.get<IAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/roles/${this.encodePathSegment(roleId)}`)
    );
  }

  /**
   * List roles
   */
  async listRoles(request: ListIAMRolesRequest): Promise<ApiResponse<ListIAMRolesResponse>> {
    return this.client.get<ListIAMRolesResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/roles`, {
        page: request.page,
        limit: request.pageSize,
      })
    );
  }

  /**
   * Update a role
   */
  async updateRole(request: UpdateIAMRoleRequest): Promise<ApiResponse<IAMRoleResponse>> {
    return this.client.put<IAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/roles/${this.encodePathSegment(request.roleId)}`),
      request
    );
  }

  /**
   * Delete a role
   */
  async deleteRole(tenantId: string, roleId: string): Promise<ApiResponse<DeleteIAMRoleResponse>> {
    return this.client.delete<DeleteIAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/roles/${this.encodePathSegment(roleId)}`)
    );
  }

  /**
   * Assign role to user
   */
  async assignRole(request: AssignIAMRoleRequest): Promise<ApiResponse<AssignIAMRoleResponse>> {
    return this.client.post<AssignIAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/users/${this.encodePathSegment(request.userId)}/roles`),
      { roleId: request.roleId }
    );
  }

  /**
   * Revoke role from user
   */
  async revokeRole(request: RevokeIAMRoleRequest): Promise<ApiResponse<RevokeIAMRoleResponse>> {
    return this.client.delete<RevokeIAMRoleResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/users/${this.encodePathSegment(request.userId)}/roles/${this.encodePathSegment(request.roleId)}`)
    );
  }

  // =========================================================================
  // Group Operations
  // =========================================================================

  /**
   * Create a group
   */
  async createGroup(request: CreateIAMGroupRequest): Promise<ApiResponse<IAMGroupResponse>> {
    return this.client.post<IAMGroupResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/groups`),
      request
    );
  }

  /**
   * Get group by ID
   */
  async getGroup(tenantId: string, groupId: string): Promise<ApiResponse<IAMGroupResponse>> {
    return this.client.get<IAMGroupResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/groups/${this.encodePathSegment(groupId)}`)
    );
  }

  /**
   * List groups
   */
  async listGroups(request: ListIAMGroupsRequest): Promise<ApiResponse<ListIAMGroupsResponse>> {
    return this.client.get<ListIAMGroupsResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/groups`, {
        page: request.page,
        limit: request.pageSize,
      })
    );
  }

  /**
   * Update a group
   */
  async updateGroup(request: UpdateIAMGroupRequest): Promise<ApiResponse<IAMGroupResponse>> {
    return this.client.put<IAMGroupResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/groups/${this.encodePathSegment(request.groupId)}`),
      request
    );
  }

  /**
   * Delete a group
   */
  async deleteGroup(tenantId: string, groupId: string): Promise<ApiResponse<DeleteIAMGroupResponse>> {
    return this.client.delete<DeleteIAMGroupResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/groups/${this.encodePathSegment(groupId)}`)
    );
  }

  /**
   * Add member to group
   */
  async addGroupMember(request: AddGroupMemberRequest): Promise<ApiResponse<AddGroupMemberResponse>> {
    return this.client.post<AddGroupMemberResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/groups/${this.encodePathSegment(request.groupId)}/members`),
      { userId: request.userId }
    );
  }

  /**
   * Remove member from group
   */
  async removeGroupMember(request: RemoveGroupMemberRequest): Promise<ApiResponse<RemoveGroupMemberResponse>> {
    return this.client.delete<RemoveGroupMemberResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/groups/${this.encodePathSegment(request.groupId)}/members/${this.encodePathSegment(request.userId)}`)
    );
  }

  // =========================================================================
  // Authentication Operations
  // =========================================================================

  /**
   * Authenticate user
   */
  async authenticate(request: AuthenticateIAMRequest): Promise<ApiResponse<AuthenticateIAMResponse>> {
    return this.client.post<AuthenticateIAMResponse>(this.buildUrl('/auth'), request);
  }

  /**
   * Check permission
   */
  async checkPermission(request: CheckIAMPermissionRequest): Promise<ApiResponse<CheckIAMPermissionResponse>> {
    return this.client.post<CheckIAMPermissionResponse>(this.buildUrl('/auth/check'), request);
  }

  /**
   * Create token
   */
  async createToken(request: CreateIAMTokenRequest): Promise<ApiResponse<CreateIAMTokenResponse>> {
    return this.client.post<CreateIAMTokenResponse>(this.buildUrl('/auth/token'), request);
  }

  /**
   * Revoke token
   */
  async revokeToken(request: RevokeIAMTokenRequest): Promise<ApiResponse<RevokeIAMTokenResponse>> {
    return this.client.post<RevokeIAMTokenResponse>(this.buildUrl('/auth/token/revoke'), request);
  }

  /**
   * Verify token
   */
  async verifyToken(request: VerifyIAMTokenRequest): Promise<ApiResponse<VerifyIAMTokenResponse>> {
    return this.client.post<VerifyIAMTokenResponse>(this.buildUrl('/auth/token/verify'), request);
  }

  // =========================================================================
  // Tenant Operations
  // =========================================================================

  /**
   * Create a tenant
   */
  async createTenant(request: CreateIAMTenantRequest): Promise<ApiResponse<IAMTenantResponse>> {
    return this.client.post<IAMTenantResponse>(this.buildUrl('/tenants'), request);
  }

  /**
   * Get tenant by ID
   */
  async getTenant(tenantId: string): Promise<ApiResponse<IAMTenantResponse>> {
    return this.client.get<IAMTenantResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}`)
    );
  }

  /**
   * List tenants
   */
  async listTenants(request?: ListIAMTenantsRequest): Promise<ApiResponse<ListIAMTenantsResponse>> {
    return this.client.get<ListIAMTenantsResponse>(this.buildUrl('/tenants', {
      page: request?.page,
      limit: request?.pageSize,
    }));
  }

  /**
   * Update a tenant
   */
  async updateTenant(request: UpdateIAMTenantRequest): Promise<ApiResponse<IAMTenantResponse>> {
    return this.client.put<IAMTenantResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}`),
      request
    );
  }

  /**
   * Delete a tenant
   */
  async deleteTenant(tenantId: string): Promise<ApiResponse<DeleteIAMTenantResponse>> {
    return this.client.delete<DeleteIAMTenantResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}`)
    );
  }

  // =========================================================================
  // Policy Operations
  // =========================================================================

  /**
   * Create a policy
   */
  async createPolicy(request: CreateIAMPolicyRequest): Promise<ApiResponse<IAMPolicyResponse>> {
    return this.client.post<IAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/policies`),
      request
    );
  }

  /**
   * Get policy by name
   */
  async getPolicy(tenantId: string, policyName: string): Promise<ApiResponse<IAMPolicyResponse>> {
    return this.client.get<IAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/policies/${this.encodePathSegment(policyName)}`)
    );
  }

  /**
   * List policies
   */
  async listPolicies(request: ListIAMPoliciesRequest): Promise<ApiResponse<ListIAMPoliciesResponse>> {
    return this.client.get<ListIAMPoliciesResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/policies`, {
        page: request.page,
        limit: request.pageSize,
      })
    );
  }

  /**
   * Update a policy
   */
  async updatePolicy(request: UpdateIAMPolicyRequest): Promise<ApiResponse<IAMPolicyResponse>> {
    return this.client.put<IAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/policies/${this.encodePathSegment(request.policyName)}`),
      request
    );
  }

  /**
   * Delete a policy
   */
  async deletePolicy(tenantId: string, policyName: string): Promise<ApiResponse<DeleteIAMPolicyResponse>> {
    return this.client.delete<DeleteIAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/policies/${this.encodePathSegment(policyName)}`)
    );
  }

  /**
   * Validate a policy
   */
  async validatePolicy(request: ValidateIAMPolicyRequest): Promise<ApiResponse<ValidateIAMPolicyResponse>> {
    return this.client.post<ValidateIAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/policies/validate`),
      request
    );
  }

  /**
   * Test a policy
   */
  async testPolicy(request: TestIAMPolicyRequest): Promise<ApiResponse<TestIAMPolicyResponse>> {
    return this.client.post<TestIAMPolicyResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/policies/test`),
      request
    );
  }

  // =========================================================================
  // Application Operations
  // =========================================================================

  /**
   * Register an application
   */
  async registerApp(request: RegisterIAMAppRequest): Promise<ApiResponse<IAMAppResponse>> {
    return this.client.post<IAMAppResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/apps`),
      request
    );
  }

  /**
   * Get application by client ID
   */
  async getApp(tenantId: string, clientId: string): Promise<ApiResponse<IAMAppResponse>> {
    return this.client.get<IAMAppResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/apps/${this.encodePathSegment(clientId)}`)
    );
  }

  /**
   * List applications
   */
  async listApps(request: ListIAMAppsRequest): Promise<ApiResponse<ListIAMAppsResponse>> {
    return this.client.get<ListIAMAppsResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/apps`, {
        page: request.page,
        limit: request.pageSize,
      })
    );
  }

  /**
   * Update an application
   */
  async updateApp(request: UpdateIAMAppRequest): Promise<ApiResponse<IAMAppResponse>> {
    return this.client.put<IAMAppResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(request.tenantId)}/apps/${this.encodePathSegment(request.clientId)}`),
      request
    );
  }

  /**
   * Delete an application
   */
  async deleteApp(tenantId: string, clientId: string): Promise<ApiResponse<DeleteIAMAppResponse>> {
    return this.client.delete<DeleteIAMAppResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/apps/${this.encodePathSegment(clientId)}`)
    );
  }

  /**
   * Rotate application secret
   */
  async rotateAppSecret(tenantId: string, clientId: string): Promise<ApiResponse<RotateIAMAppSecretResponse>> {
    return this.client.post<RotateIAMAppSecretResponse>(
      this.buildUrl(`/tenants/${this.encodePathSegment(tenantId)}/apps/${this.encodePathSegment(clientId)}/rotate-secret`),
      {}
    );
  }
}
