/**
 * Invitation Service
 *
 * Provides operations for tenant invitation management including creating,
 * listing, and revoking invitations.
 */

import type { ApiClient } from '../client/api-client.js';
import type { ApiResponse } from '../types/api.js';
import { BaseService } from './base-service.js';
import type {
  CreateInvitationRequest,
  CreateInvitationResponse,
  GetInvitationResponse,
  GetInvitationByTokenResponse,
  ListInvitationsRequest,
  ListInvitationsResponse,
  RevokeInvitationResponse,
  AcceptInvitationRequest,
  AcceptInvitationResponse,
} from '../types/invitation.js';

/**
 * Invitation Service class
 *
 * @example
 * ```typescript
 * const client = new PlatformClient({ baseUrl: 'https://api.example.com' });
 *
 * // Create an invitation
 * const invitation = await client.invitation.create({
 *   email: 'user@example.com',
 *   role: 'member',
 *   expiresIn: 72, // hours
 * });
 *
 * // List pending invitations
 * const invitations = await client.invitation.list({
 *   status: 'pending',
 *   page: 1,
 *   pageSize: 20,
 * });
 *
 * // Revoke an invitation
 * await client.invitation.revoke(invitation.data.invitation.id);
 * ```
 */
export class InvitationService extends BaseService {
  /**
   * Creates a new Invitation service instance
   *
   * @param client - The API client to use for requests
   */
  constructor(client: ApiClient) {
    super(client, '/v1/invitations');
  }

  // =========================================================================
  // Invitation CRUD Operations
  // =========================================================================

  /**
   * Create an invitation
   *
   * @param request - Invitation creation request
   * @returns Created invitation with token and invite URL
   */
  async create(request: CreateInvitationRequest): Promise<ApiResponse<CreateInvitationResponse>> {
    return this.client.post<CreateInvitationResponse>(this.buildUrl(''), request);
  }

  /**
   * Get invitation by ID
   *
   * @param id - Invitation ID
   * @returns Invitation information
   */
  async get(id: string): Promise<ApiResponse<GetInvitationResponse>> {
    return this.client.get<GetInvitationResponse>(
      this.buildUrl(`/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Get invitation by token
   *
   * @param token - Invitation token
   * @returns Invitation information
   */
  async getByToken(token: string): Promise<ApiResponse<GetInvitationByTokenResponse>> {
    return this.client.get<GetInvitationByTokenResponse>(
      this.buildUrl(`/token/${this.encodePathSegment(token)}`)
    );
  }

  /**
   * List invitations
   *
   * @param request - List request with filters
   * @returns List of invitations
   */
  async list(request?: ListInvitationsRequest): Promise<ApiResponse<ListInvitationsResponse>> {
    return this.client.get<ListInvitationsResponse>(this.buildUrl('', {
      page: request?.page,
      limit: request?.pageSize,
      filters: {
        status: request?.status,
        email: request?.email,
      },
    }));
  }

  /**
   * Revoke an invitation
   *
   * @param id - Invitation ID
   * @returns Revocation result
   */
  async revoke(id: string): Promise<ApiResponse<RevokeInvitationResponse>> {
    return this.client.delete<RevokeInvitationResponse>(
      this.buildUrl(`/${this.encodePathSegment(id)}`)
    );
  }

  /**
   * Accept an invitation
   *
   * @param request - Accept invitation request with token
   * @returns Acceptance result with user and tenant information
   */
  async accept(request: AcceptInvitationRequest): Promise<ApiResponse<AcceptInvitationResponse>> {
    return this.client.post<AcceptInvitationResponse>(
      this.buildUrl(`/accept`),
      request
    );
  }

  /**
   * Resend an invitation email
   *
   * @param id - Invitation ID
   * @returns Updated invitation with new expiration
   */
  async resend(id: string): Promise<ApiResponse<CreateInvitationResponse>> {
    return this.client.post<CreateInvitationResponse>(
      this.buildUrl(`/${this.encodePathSegment(id)}/resend`),
      {}
    );
  }
}
