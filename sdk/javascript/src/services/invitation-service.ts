/**
 * Invitation Service
 *
 * Provides operations for tenant invitation management including creating,
 * listing, and revoking invitations.
 */

import type { ApiClient } from '../client/api-client.js';
import type { Transport } from '../transport/transport.js';
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
  Invitation,
  InvitationStatus,
} from '../types/invitation.js';

/**
 * The served routes write the proto InvitationStatus enum by its protojson
 * name; this maps each name to the lower-case InvitationStatus the SDK type
 * declares.
 */
const SERVED_INVITATION_STATUS: Record<string, InvitationStatus> = {
  INVITATION_STATUS_PENDING: 'pending',
  INVITATION_STATUS_ACCEPTED: 'accepted',
  INVITATION_STATUS_EXPIRED: 'expired',
  INVITATION_STATUS_REVOKED: 'revoked',
};

/**
 * Returns a copy of a successful reply whose invitation status is the
 * lower-case InvitationStatus; a status that is not one of the four enum
 * names, and any other reply, is returned as it is.
 */
function withInvitationStatus<T extends { invitation?: Invitation }>(
  response: ApiResponse<T>
): ApiResponse<T> {
  const invitation = response.success ? response.data?.invitation : undefined;
  if (!invitation) {
    return response;
  }
  const status = Object.prototype.hasOwnProperty.call(SERVED_INVITATION_STATUS, invitation.status)
    ? SERVED_INVITATION_STATUS[invitation.status]
    : invitation.status;
  return {
    ...response,
    data: { ...response.data, invitation: { ...invitation, status } } as T,
  };
}

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
  constructor(client: Transport | ApiClient) {
    super(client, '/v1/invitations');
  }

  // =========================================================================
  // Invitation CRUD Operations
  // =========================================================================

  /**
   * Create an invitation
   *
   * The request's expiresIn is in hours; it is sent as expiresInSeconds
   * (hours * 3600), the field the server's CreateInvitationRequest reads.
   * expiresIn itself is never sent. When expiresIn is omitted no expiry
   * field is sent and the server applies its default. An expiresIn that is
   * not a finite number > 0, or rounds to 0 seconds, throws before posting:
   * the server would silently replace it with its default.
   *
   * @param request - Invitation creation request
   * @returns Created invitation with token and invite URL
   */
  async create(request: CreateInvitationRequest): Promise<ApiResponse<CreateInvitationResponse>> {
    const body: { email: string; role: CreateInvitationRequest['role']; expiresInSeconds?: number } = {
      email: request.email,
      role: request.role,
    };
    if (request.expiresIn !== undefined) {
      const hours = request.expiresIn;
      const seconds = Number.isFinite(hours) && hours > 0 ? Math.round(hours * 3600) : 0;
      if (seconds <= 0) {
        throw new Error(`invitation expiresIn must be a positive number of hours, got ${String(hours)}`);
      }
      body.expiresInSeconds = seconds;
    }
    return this.client.post<CreateInvitationResponse>(this.buildUrl(''), body);
  }

  /**
   * Get invitation by ID
   *
   * The served status is the protojson enum name and is returned as the
   * lower-case InvitationStatus.
   *
   * @param id - Invitation ID
   * @returns Invitation information
   */
  async get(id: string): Promise<ApiResponse<GetInvitationResponse>> {
    const response = await this.client.get<GetInvitationResponse>(
      this.buildUrl(`/${this.encodePathSegment(id)}`)
    );
    return withInvitationStatus(response);
  }

  /**
   * Get invitation by token
   *
   * The served status is the protojson enum name and is returned as the
   * lower-case InvitationStatus.
   *
   * @param token - Invitation token
   * @returns Invitation information
   */
  async getByToken(token: string): Promise<ApiResponse<GetInvitationByTokenResponse>> {
    const response = await this.client.get<GetInvitationByTokenResponse>(
      this.buildUrl(`/token/${this.encodePathSegment(token)}`)
    );
    return withInvitationStatus(response);
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
   * Marks the invitation revoked (POST /api/v1/invitations/{id}/revoke).
   * It does not delete the invitation: the record and its history stay.
   *
   * @param id - Invitation ID
   * @returns Revocation result
   */
  async revoke(id: string): Promise<ApiResponse<RevokeInvitationResponse>> {
    return this.client.post<RevokeInvitationResponse>(
      this.buildUrl(`/${this.encodePathSegment(id)}/revoke`),
      {}
    );
  }

  /**
   * Accept an invitation
   *
   * POST /api/v1/invitations/accept with the body { token, userId } only.
   *
   * @param request - Accept invitation request with token
   * @returns The operation status and the accepted invitation
   */
  async accept(request: AcceptInvitationRequest): Promise<ApiResponse<AcceptInvitationResponse>> {
    return this.client.post<AcceptInvitationResponse>(
      this.buildUrl(`/accept`),
      { token: request.token, userId: request.userId }
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
