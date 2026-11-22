/**
 * Invitation React Hook
 *
 * Provides React hooks for invitation management with built-in
 * state management for queries and mutations.
 *
 * @packageDocumentation
 */

import type { InvitationService } from '../../services/invitation-service.js';
import type {
  CreateInvitationRequest,
  CreateInvitationResponse,
  ListInvitationsRequest,
  ListInvitationsResponse,
  RevokeInvitationResponse,
  AcceptInvitationRequest,
  AcceptInvitationResponse,
  GetInvitationResponse,
  GetInvitationByTokenResponse,
} from '../../types/invitation.js';
import type { ApiResponse } from '../../types/api.js';
import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import type { UseMutationResult } from './use-mutation.js';
import type { UseApiResult } from './use-api.js';

/**
 * Result returned by the useInvitation hook
 */
export interface UseInvitationResult {
  /** The invitation service instance */
  service: InvitationService;

  /** Mutation for creating invitations */
  create: UseMutationResult<CreateInvitationResponse, CreateInvitationRequest>;

  /** Mutation for revoking invitations */
  revoke: UseMutationResult<RevokeInvitationResponse, string>;

  /** Mutation for accepting invitations */
  accept: UseMutationResult<AcceptInvitationResponse, AcceptInvitationRequest>;

  /** Mutation for resending invitation emails */
  resend: UseMutationResult<CreateInvitationResponse, string>;
}

/**
 * Hook for invitation management
 *
 * Provides access to the invitation service with pre-configured mutations
 * for common operations like creating, revoking, and accepting invitations.
 *
 * @returns Object with invitation service and mutation helpers
 *
 * @example
 * ```tsx
 * function InvitationManager() {
 *   const { create, revoke, service } = useInvitation();
 *
 *   const handleInvite = async (email: string, role: string) => {
 *     create.mutate({
 *       email,
 *       role,
 *       expiresIn: 72,
 *     });
 *   };
 *
 *   const handleRevoke = (id: string) => {
 *     revoke.mutate(id);
 *   };
 *
 *   return (
 *     <div>
 *       <button
 *         onClick={() => handleInvite('user@example.com', 'member')}
 *         disabled={create.isLoading}
 *       >
 *         {create.isLoading ? 'Sending...' : 'Send Invitation'}
 *       </button>
 *       {create.isError && <p>Error: {create.error?.message}</p>}
 *       {create.isSuccess && <p>Invitation sent!</p>}
 *     </div>
 *   );
 * }
 * ```
 */
export function useInvitation(): UseInvitationResult {
  const client = usePlatformClient();
  const service = client.invitation;

  const create = useMutation<CreateInvitationResponse, CreateInvitationRequest>(
    (request: CreateInvitationRequest): Promise<ApiResponse<CreateInvitationResponse>> =>
      service.create(request)
  );

  const revoke = useMutation<RevokeInvitationResponse, string>(
    (id: string): Promise<ApiResponse<RevokeInvitationResponse>> =>
      service.revoke(id)
  );

  const accept = useMutation<AcceptInvitationResponse, AcceptInvitationRequest>(
    (request: AcceptInvitationRequest): Promise<ApiResponse<AcceptInvitationResponse>> =>
      service.accept(request)
  );

  const resend = useMutation<CreateInvitationResponse, string>(
    (id: string): Promise<ApiResponse<CreateInvitationResponse>> =>
      service.resend(id)
  );

  return {
    service,
    create,
    revoke,
    accept,
    resend,
  };
}

/**
 * Options for the useInvitationList hook
 */
export interface UseInvitationListOptions {
  /** Whether the query should be enabled */
  enabled?: boolean;
  /** Interval in milliseconds to automatically refetch data */
  refetchInterval?: number;
  /** Filter parameters */
  filters?: ListInvitationsRequest;
}

/**
 * Hook for listing invitations with automatic data fetching
 *
 * Provides a declarative way to fetch and display invitations with
 * automatic state management for loading, error, and data states.
 *
 * @param options - Configuration options
 * @returns Query result with invitations data and state
 *
 * @example
 * ```tsx
 * function InvitationList() {
 *   const { data, isLoading, error, refetch } = useInvitationList({
 *     filters: { status: 'pending' },
 *     refetchInterval: 30000,
 *   });
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <ul>
 *       {data?.invitations.map(inv => (
 *         <li key={inv.id}>
 *           {inv.email} - {inv.status}
 *         </li>
 *       ))}
 *     </ul>
 *   );
 * }
 * ```
 */
export function useInvitationList(
  options?: UseInvitationListOptions
): UseApiResult<ListInvitationsResponse> {
  const client = usePlatformClient();
  const service = client.invitation;

  const apiOptions: {
    enabled?: boolean;
    refetchInterval?: number;
  } = {};

  if (options?.enabled !== undefined) {
    apiOptions.enabled = options.enabled;
  }

  if (options?.refetchInterval !== undefined) {
    apiOptions.refetchInterval = options.refetchInterval;
  }

  return useApi<ListInvitationsResponse>(
    () => service.list(options?.filters),
    [
      options?.filters?.page,
      options?.filters?.pageSize,
      options?.filters?.status,
      options?.filters?.email,
    ],
    Object.keys(apiOptions).length > 0 ? apiOptions : undefined
  );
}

/**
 * Options for the single-invitation read hooks.
 */
export interface UseInvitationGetOptions {
  /** Whether the query runs (default: true). An undefined or empty key always disables it. */
  enabled?: boolean;
  /** Refetch interval in milliseconds. */
  refetchInterval?: number;
}

function invitationGetApiOptions(
  key: string | undefined,
  options?: UseInvitationGetOptions
): { enabled?: boolean; refetchInterval?: number } | undefined {
  const apiOptions: {
    enabled?: boolean;
    refetchInterval?: number;
  } = {};

  if (key === undefined || key === '' || options?.enabled === false) {
    apiOptions.enabled = false;
  } else if (options?.enabled !== undefined) {
    apiOptions.enabled = options.enabled;
  }

  if (options?.refetchInterval !== undefined) {
    apiOptions.refetchInterval = options.refetchInterval;
  }

  return Object.keys(apiOptions).length > 0 ? apiOptions : undefined;
}

/**
 * Hook for reading one invitation by ID (GET /api/v1/invitations/{id}).
 *
 * The query is disabled while the ID is undefined or empty.
 *
 * @example
 * ```tsx
 * const { data, loading, error, refetch } = useInvitationGet(invitationId);
 * ```
 */
export function useInvitationGet(
  id: string | undefined,
  options?: UseInvitationGetOptions
): UseApiResult<GetInvitationResponse> {
  const client = usePlatformClient();
  const service = client.invitation;

  return useApi<GetInvitationResponse>(
    () => service.get(id as string),
    [id],
    invitationGetApiOptions(id, options)
  );
}

/**
 * Hook for reading one invitation by its token
 * (GET /api/v1/invitations/token/{token}).
 *
 * The query is disabled while the token is undefined or empty.
 *
 * @example
 * ```tsx
 * const { data, loading, error } = useInvitationGetByToken(token);
 * ```
 */
export function useInvitationGetByToken(
  token: string | undefined,
  options?: UseInvitationGetOptions
): UseApiResult<GetInvitationByTokenResponse> {
  const client = usePlatformClient();
  const service = client.invitation;

  return useApi<GetInvitationByTokenResponse>(
    () => service.getByToken(token as string),
    [token],
    invitationGetApiOptions(token, options)
  );
}
