/**
 * QuicBaaS IAM Service
 *
 * Provides identity and access management operations for QuicBaaS including
 * user management, group management, and policy attachment.
 */

import type { ApiClient } from '../../client/api-client.js';
import type { ApiResponse } from '../../types/api.js';
import { BaseService } from '../base-service.js';
import type {
  CreateQuicBaaSUserRequest,
  CreateQuicBaaSUserResponse,
  GetQuicBaaSUserRequest,
  GetQuicBaaSUserResponse,
  UpdateQuicBaaSUserRequest,
  UpdateQuicBaaSUserResponse,
  DeleteQuicBaaSUserRequest,
  DeleteQuicBaaSUserResponse,
  ListQuicBaaSUsersRequest,
  ListQuicBaaSUsersResponse,
  CreateQuicBaaSGroupRequest,
  CreateQuicBaaSGroupResponse,
  AddUserToGroupRequest,
  AddUserToGroupResponse,
  RemoveUserFromGroupRequest,
  RemoveUserFromGroupResponse,
  CreateQuicBaaSPolicyRequest,
  CreateQuicBaaSPolicyResponse,
  AttachPolicyRequest,
  AttachPolicyResponse,
  DetachPolicyRequest,
  DetachPolicyResponse,
} from '../../types/quicbaas/infrastructure-part2.js';

/**
 * QuicBaaS IAM Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create a user
 * const user = await client.quicbaas.iam.createUser({
 *   username: 'john.doe',
 *   email: 'john.doe@example.com',
 *   displayName: 'John Doe',
 * });
 *
 * // Create a group and add user
 * const group = await client.quicbaas.iam.createGroup({
 *   name: 'developers',
 *   description: 'Development team',
 * });
 *
 * await client.quicbaas.iam.addUserToGroup({
 *   groupId: group.data.group.id,
 *   userId: user.data.user.id,
 * });
 *
 * // Create and attach a policy
 * const policy = await client.quicbaas.iam.createPolicy({
 *   name: 'read-only',
 *   description: 'Read-only access',
 *   document: JSON.stringify({
 *     version: '2012-10-17',
 *     statement: [{
 *       effect: 'Allow',
 *       action: ['quicbaas:Get*', 'quicbaas:List*'],
 *       resource: '*',
 *     }],
 *   }),
 * });
 *
 * await client.quicbaas.iam.attachPolicy({
 *   policyId: policy.data.policy.id,
 *   targetType: 'group',
 *   targetId: group.data.group.id,
 * });
 * ```
 */
export class QuicBaaSIAMService extends BaseService {
  /**
   * Creates a new QuicBaaS IAM service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/quicbaas');
  }

  // =========================================================================
  // User Management
  // =========================================================================

  /**
   * Create a new QuicBaaS user
   *
   * @param request - User creation request
   * @returns Created user with optional initial access key
   */
  async createUser(request: CreateQuicBaaSUserRequest): Promise<ApiResponse<CreateQuicBaaSUserResponse>> {
    return this.client.post<CreateQuicBaaSUserResponse>(
      this.buildUrl('/iam/users'),
      request
    );
  }

  /**
   * Get a user by ID
   *
   * @param request - Get user request
   * @returns User details
   */
  async getUser(request: GetQuicBaaSUserRequest): Promise<ApiResponse<GetQuicBaaSUserResponse>> {
    return this.client.get<GetQuicBaaSUserResponse>(
      this.buildUrl(`/iam/users/${this.encodePathSegment(request.userId)}`)
    );
  }

  /**
   * Update an existing user
   *
   * @param request - User update request
   * @returns Updated user
   */
  async updateUser(request: UpdateQuicBaaSUserRequest): Promise<ApiResponse<UpdateQuicBaaSUserResponse>> {
    const { userId, ...body } = request;
    return this.client.put<UpdateQuicBaaSUserResponse>(
      this.buildUrl(`/iam/users/${this.encodePathSegment(userId)}`),
      body
    );
  }

  /**
   * Delete a user
   *
   * @param request - Delete user request
   * @returns Deletion result
   */
  async deleteUser(request: DeleteQuicBaaSUserRequest): Promise<ApiResponse<DeleteQuicBaaSUserResponse>> {
    return this.client.delete<DeleteQuicBaaSUserResponse>(
      this.buildUrl(`/iam/users/${this.encodePathSegment(request.userId)}`)
    );
  }

  /**
   * List all users with optional filtering
   *
   * @param request - List users request with optional filters
   * @returns List of users
   */
  async listUsers(request?: ListQuicBaaSUsersRequest): Promise<ApiResponse<ListQuicBaaSUsersResponse>> {
    const filters: Record<string, string | undefined> = {};

    if (request?.status !== undefined) {
      filters.status = request.status;
    }
    if (request?.groupId !== undefined) {
      filters.groupId = request.groupId;
    }

    return this.client.get<ListQuicBaaSUsersResponse>(
      this.buildUrl('/iam/users', {
        page: request?.page,
        limit: request?.pageSize,
        filters,
      })
    );
  }

  // =========================================================================
  // Group Management
  // =========================================================================

  /**
   * Create a new group
   *
   * @param request - Group creation request
   * @returns Created group
   */
  async createGroup(request: CreateQuicBaaSGroupRequest): Promise<ApiResponse<CreateQuicBaaSGroupResponse>> {
    return this.client.post<CreateQuicBaaSGroupResponse>(
      this.buildUrl('/iam/groups'),
      request
    );
  }

  /**
   * Add a user to a group
   *
   * @param request - Add user to group request
   * @returns Operation result
   */
  async addUserToGroup(request: AddUserToGroupRequest): Promise<ApiResponse<AddUserToGroupResponse>> {
    return this.client.post<AddUserToGroupResponse>(
      this.buildUrl(`/iam/groups/${this.encodePathSegment(request.groupId)}/members`),
      { userId: request.userId }
    );
  }

  /**
   * Remove a user from a group
   *
   * @param request - Remove user from group request
   * @returns Operation result
   */
  async removeUserFromGroup(request: RemoveUserFromGroupRequest): Promise<ApiResponse<RemoveUserFromGroupResponse>> {
    return this.client.delete<RemoveUserFromGroupResponse>(
      this.buildUrl(
        `/iam/groups/${this.encodePathSegment(request.groupId)}/members/${this.encodePathSegment(request.userId)}`
      )
    );
  }

  // =========================================================================
  // Policy Management
  // =========================================================================

  /**
   * Create a new policy
   *
   * @param request - Policy creation request
   * @returns Created policy
   */
  async createPolicy(request: CreateQuicBaaSPolicyRequest): Promise<ApiResponse<CreateQuicBaaSPolicyResponse>> {
    return this.client.post<CreateQuicBaaSPolicyResponse>(
      this.buildUrl('/iam/policies'),
      request
    );
  }

  /**
   * Attach a policy to a user or group
   *
   * @param request - Attach policy request
   * @returns Operation result
   */
  async attachPolicy(request: AttachPolicyRequest): Promise<ApiResponse<AttachPolicyResponse>> {
    const targetPath = request.targetType === 'user' ? 'users' : 'groups';
    return this.client.post<AttachPolicyResponse>(
      this.buildUrl(`/iam/${targetPath}/${this.encodePathSegment(request.targetId)}/policies`),
      { policyId: request.policyId }
    );
  }

  /**
   * Detach a policy from a user or group
   *
   * @param request - Detach policy request
   * @returns Operation result
   */
  async detachPolicy(request: DetachPolicyRequest): Promise<ApiResponse<DetachPolicyResponse>> {
    const targetPath = request.targetType === 'user' ? 'users' : 'groups';
    return this.client.delete<DetachPolicyResponse>(
      this.buildUrl(
        `/iam/${targetPath}/${this.encodePathSegment(request.targetId)}/policies/${this.encodePathSegment(request.policyId)}`
      )
    );
  }
}
