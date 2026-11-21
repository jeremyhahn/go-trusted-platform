/**
 * Invitation Types
 *
 * Types for tenant invitation operations including creating, listing, and revoking invitations.
 */

// =============================================================================
// Enums
// =============================================================================

/**
 * Invitation status
 */
export type InvitationStatus = 'pending' | 'accepted' | 'expired' | 'revoked';

// =============================================================================
// Data Types
// =============================================================================

/**
 * Invitation information
 */
export interface Invitation {
  /** Invitation ID */
  id: string;
  /** Invitation token */
  token: string;
  /** Tenant ID */
  tenantId: string;
  /** Invited email address */
  email: string;
  /** Assigned role */
  role: string;
  /** Invitation status */
  status: InvitationStatus;
  /** Expiration timestamp */
  expiresAt: string;
  /** Creation timestamp */
  createdAt: string;
  /** Acceptance timestamp */
  acceptedAt?: string;
  /** ID of user who sent the invitation */
  invitedById: string;
  /** Full invite URL for the recipient */
  inviteUrl?: string;
}

// =============================================================================
// Request Types
// =============================================================================

/**
 * Create invitation request
 */
export interface CreateInvitationRequest {
  /** Email address to invite */
  email: string;
  /** Role to assign */
  role: string;
  /** Expiration time in hours */
  expiresIn?: number;
}

/**
 * Get invitation request
 */
export interface GetInvitationRequest {
  /** Invitation ID */
  id: string;
}

/**
 * Get invitation by token request
 */
export interface GetInvitationByTokenRequest {
  /** Invitation token */
  token: string;
}

/**
 * List invitations request
 */
export interface ListInvitationsRequest {
  /** Page number */
  page?: number;
  /** Page size */
  pageSize?: number;
  /** Filter by status */
  status?: InvitationStatus;
  /** Filter by email */
  email?: string;
}

/**
 * Revoke invitation request
 */
export interface RevokeInvitationRequest {
  /** Invitation ID */
  id: string;
}

/**
 * Accept invitation request
 */
export interface AcceptInvitationRequest {
  /** Invitation token */
  token: string;
  /** ID of the accepting user, a decimal uint64 (wire field user_id) */
  userId: string;
}

// =============================================================================
// Response Types
// =============================================================================

/**
 * Operation status
 */
export interface InvitationStatus2 {
  /** Whether succeeded */
  success: boolean;
  /** Status message */
  message: string;
  /** Error details */
  error?: {
    code: string;
    message: string;
    metadata?: Record<string, string>;
  };
}

/**
 * Pagination response
 */
export interface InvitationPaginationResponse {
  /** Current page */
  page: number;
  /** Page size */
  pageSize: number;
  /** Total pages */
  totalPages: number;
  /** Total items */
  totalItems: number;
}

/**
 * Create invitation response
 */
export interface CreateInvitationResponse {
  /** Created invitation */
  invitation: Invitation;
}

/**
 * Get invitation response
 */
export interface GetInvitationResponse {
  /** Invitation */
  invitation: Invitation;
}

/**
 * Get invitation by token response
 */
export interface GetInvitationByTokenResponse {
  /** Invitation */
  invitation: Invitation;
}

/**
 * List invitations response
 */
export interface ListInvitationsResponse {
  /** Invitations */
  invitations: Invitation[];
  /** Total count */
  total: number;
  /** Pagination info */
  pagination?: InvitationPaginationResponse;
}

/**
 * Revoke invitation response
 */
export interface RevokeInvitationResponse {
  /** Operation status */
  success: boolean;
  /** Status message */
  message?: string;
}

/**
 * Accept invitation response
 */
export interface AcceptInvitationResponse {
  /** Operation status */
  success: boolean;
  /** User ID (if user was created or associated) */
  userId?: string;
  /** Tenant ID */
  tenantId?: string;
  /** Status message */
  message?: string;
}
