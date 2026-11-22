/**
 * EAB React Hook
 *
 * Provides React hooks for EAB credential management with built-in
 * state management for queries and mutations.
 *
 * @packageDocumentation
 */

import type { EABService } from '../../services/eab-service.js';
import type {
  CreateEABCredentialRequest,
  CreateEABCredentialResponse,
  ListEABCredentialsRequest,
  ListEABCredentialsResponse,
  RevokeEABCredentialResponse,
  ValidateEABCredentialRequest,
  ValidateEABCredentialResponse,
  DeleteEABCredentialResponse,
  GetEABQRCodeResponse,
  GetEnrollmentURLResponse,
  MarkEABCredentialUsedResponse,
  CleanupExpiredEABCredentialsRequest,
  CleanupExpiredEABCredentialsResponse,
} from '../../types/eab.js';
import type { ApiResponse } from '../../types/api.js';
import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import type { UseMutationResult } from './use-mutation.js';
import type { UseApiResult } from './use-api.js';

/**
 * Result returned by the useEAB hook
 */
export interface UseEABResult {
  /** The EAB service instance */
  service: EABService;

  /** Mutation for creating EAB credentials */
  create: UseMutationResult<CreateEABCredentialResponse, CreateEABCredentialRequest>;

  /** Mutation for revoking EAB credentials */
  revoke: UseMutationResult<RevokeEABCredentialResponse, string>;

  /** Mutation for validating EAB credentials */
  validate: UseMutationResult<ValidateEABCredentialResponse, ValidateEABCredentialRequest>;

  /** Mutation for deleting EAB credentials */
  deleteCredential: UseMutationResult<DeleteEABCredentialResponse, string>;

  /** Mutation for getting QR code */
  getQRCode: UseMutationResult<GetEABQRCodeResponse, { id: string; size?: number }>;

  /** Mutation for getting enrollment URL */
  getEnrollmentURL: UseMutationResult<GetEnrollmentURLResponse, string>;

  /** Mutation for marking a credential used */
  markUsed: UseMutationResult<MarkEABCredentialUsedResponse, string>;

  /** Mutation for deleting expired credentials */
  cleanupExpired: UseMutationResult<
    CleanupExpiredEABCredentialsResponse,
    CleanupExpiredEABCredentialsRequest | undefined
  >;
}

/**
 * Hook for EAB credential management
 *
 * Provides access to the EAB service with pre-configured mutations
 * for common operations like creating, revoking, and validating credentials.
 *
 * @returns Object with EAB service and mutation helpers
 *
 * @example
 * ```tsx
 * function EABManager() {
 *   const { create, revoke, service } = useEAB();
 *
 *   const handleCreate = async (profileId: string, tenantId: string) => {
 *     create.mutate({
 *       profileId,
 *       tenantId,
 *       expiresInSeconds: 86400,
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
 *         onClick={() => handleCreate(1, 'tenant-123')}
 *         disabled={create.isLoading}
 *       >
 *         {create.isLoading ? 'Creating...' : 'Create Credential'}
 *       </button>
 *       {create.isError && <p>Error: {create.error?.message}</p>}
 *       {create.isSuccess && <p>Credential created!</p>}
 *     </div>
 *   );
 * }
 * ```
 */
export function useEAB(): UseEABResult {
  const client = usePlatformClient();
  const service = client.eab;

  const create = useMutation<CreateEABCredentialResponse, CreateEABCredentialRequest>(
    (request: CreateEABCredentialRequest): Promise<ApiResponse<CreateEABCredentialResponse>> =>
      service.create(request)
  );

  const revoke = useMutation<RevokeEABCredentialResponse, string>(
    (id: string): Promise<ApiResponse<RevokeEABCredentialResponse>> =>
      service.revoke(id)
  );

  const validate = useMutation<ValidateEABCredentialResponse, ValidateEABCredentialRequest>(
    (request: ValidateEABCredentialRequest): Promise<ApiResponse<ValidateEABCredentialResponse>> =>
      service.validate(request)
  );

  const deleteCredential = useMutation<DeleteEABCredentialResponse, string>(
    (id: string): Promise<ApiResponse<DeleteEABCredentialResponse>> =>
      service.delete(id)
  );

  const getQRCode = useMutation<GetEABQRCodeResponse, { id: string; size?: number }>(
    (params: { id: string; size?: number }): Promise<ApiResponse<GetEABQRCodeResponse>> =>
      service.getQRCode(params.id, params.size)
  );

  const getEnrollmentURL = useMutation<GetEnrollmentURLResponse, string>(
    (id: string): Promise<ApiResponse<GetEnrollmentURLResponse>> =>
      service.getEnrollmentURL(id)
  );

  const markUsed = useMutation<MarkEABCredentialUsedResponse, string>(
    (id: string): Promise<ApiResponse<MarkEABCredentialUsedResponse>> =>
      service.markUsed(id)
  );

  const cleanupExpired = useMutation<
    CleanupExpiredEABCredentialsResponse,
    CleanupExpiredEABCredentialsRequest | undefined
  >(
    (
      request: CleanupExpiredEABCredentialsRequest | undefined
    ): Promise<ApiResponse<CleanupExpiredEABCredentialsResponse>> =>
      service.cleanupExpired(request)
  );

  return {
    service,
    create,
    revoke,
    validate,
    deleteCredential,
    getQRCode,
    getEnrollmentURL,
    markUsed,
    cleanupExpired,
  };
}

/**
 * Options for the useEABList hook
 */
export interface UseEABListOptions {
  /** Whether the query should be enabled */
  enabled?: boolean;
  /** Interval in milliseconds to automatically refetch data */
  refetchInterval?: number;
  /** Filter parameters */
  filters?: ListEABCredentialsRequest;
}

/**
 * Hook for listing EAB credentials with automatic data fetching
 *
 * Provides a declarative way to fetch and display EAB credentials with
 * automatic state management for loading, error, and data states.
 *
 * @param options - Configuration options
 * @returns Query result with credentials data and state
 *
 * @example
 * ```tsx
 * function EABList() {
 *   const { data, isLoading, error, refetch } = useEABList({
 *     filters: { status: 'ACTIVE', tenantId: 'tenant-123' },
 *     refetchInterval: 30000,
 *   });
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <ul>
 *       {data?.credentials.map(cred => (
 *         <li key={cred.id}>
 *           {cred.keyId} - {cred.status}
 *         </li>
 *       ))}
 *     </ul>
 *   );
 * }
 * ```
 */
export function useEABList(
  options?: UseEABListOptions
): UseApiResult<ListEABCredentialsResponse> {
  const client = usePlatformClient();
  const service = client.eab;

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

  return useApi<ListEABCredentialsResponse>(
    () => service.list(options?.filters),
    [
      options?.filters?.page,
      options?.filters?.pageSize,
      options?.filters?.status,
      options?.filters?.tenantId,
      options?.filters?.profileId,
    ],
    Object.keys(apiOptions).length > 0 ? apiOptions : undefined
  );
}
