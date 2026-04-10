/**
 * vTPM Instance React Hook
 *
 * Provides React hooks for vTPM instance management with built-in
 * state management for queries and mutations.
 *
 * @packageDocumentation
 */

import type { VTPMService } from '../../services/vtpm-service.js';
import type {
  CreateVTPMInstanceRequest,
  CreateVTPMInstanceResponse,
  ListVTPMInstancesRequest,
  ListVTPMInstancesResponse,
  DeleteVTPMInstanceResponse,
  StartVTPMInstanceResponse,
  StopVTPMInstanceResponse,
  GetVTPMInstanceStatusResponse,
  GetVTPMInstanceEKCertResponse,
  GetVTPMInstanceEKFingerprintResponse,
} from '../../types/vtpm.js';
import type { ApiResponse } from '../../types/api.js';
import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import type { UseMutationResult } from './use-mutation.js';
import type { UseApiResult } from './use-api.js';

/**
 * Result returned by the useVTPMInstance hook
 */
export interface UseVTPMInstanceResult {
  /** The vTPM service instance */
  service: VTPMService;

  /** Mutation for creating vTPM instances */
  create: UseMutationResult<CreateVTPMInstanceResponse, CreateVTPMInstanceRequest>;

  /** Mutation for deleting vTPM instances */
  deleteInstance: UseMutationResult<DeleteVTPMInstanceResponse, { id: string; force?: boolean }>;

  /** Mutation for starting vTPM instances */
  start: UseMutationResult<StartVTPMInstanceResponse, string>;

  /** Mutation for stopping vTPM instances */
  stop: UseMutationResult<StopVTPMInstanceResponse, { id: string; force?: boolean }>;

  /** Mutation for getting vTPM instance status */
  getStatus: UseMutationResult<GetVTPMInstanceStatusResponse, string>;

  /** Mutation for getting vTPM instance EK certificate */
  getEKCert: UseMutationResult<GetVTPMInstanceEKCertResponse, { id: string; format?: 'pem' | 'der' }>;

  /** Mutation for getting vTPM instance EK fingerprint */
  getEKFingerprint: UseMutationResult<GetVTPMInstanceEKFingerprintResponse, { id: string; algorithm?: 'sha256' | 'sha384' | 'sha512' }>;
}

/**
 * Hook for vTPM instance management
 *
 * Provides access to the vTPM service with pre-configured mutations
 * for common operations like creating, starting, stopping, and managing instances.
 *
 * @returns Object with vTPM service and mutation helpers
 *
 * @example
 * ```tsx
 * function VTPMInstanceManager() {
 *   const { create, start, stop, service } = useVTPMInstance();
 *
 *   const handleCreate = async (profileId: number) => {
 *     create.mutate({
 *       profileId,
 *       config: { tpmVersion: '2.0' },
 *     });
 *   };
 *
 *   const handleStart = (id: string) => {
 *     start.mutate(id);
 *   };
 *
 *   const handleStop = (id: string) => {
 *     stop.mutate({ id, force: false });
 *   };
 *
 *   return (
 *     <div>
 *       <button
 *         onClick={() => handleCreate(1)}
 *         disabled={create.isLoading}
 *       >
 *         {create.isLoading ? 'Creating...' : 'Create Instance'}
 *       </button>
 *       {create.isError && <p>Error: {create.error?.message}</p>}
 *       {create.isSuccess && <p>Instance created!</p>}
 *     </div>
 *   );
 * }
 * ```
 */
export function useVTPMInstance(): UseVTPMInstanceResult {
  const client = usePlatformClient();
  const service = client.vtpm;

  const create = useMutation<CreateVTPMInstanceResponse, CreateVTPMInstanceRequest>(
    (request: CreateVTPMInstanceRequest): Promise<ApiResponse<CreateVTPMInstanceResponse>> =>
      service.create(request)
  );

  const deleteInstance = useMutation<DeleteVTPMInstanceResponse, { id: string; force?: boolean }>(
    (params: { id: string; force?: boolean }): Promise<ApiResponse<DeleteVTPMInstanceResponse>> =>
      service.delete(params.id, params.force)
  );

  const start = useMutation<StartVTPMInstanceResponse, string>(
    (id: string): Promise<ApiResponse<StartVTPMInstanceResponse>> =>
      service.start(id)
  );

  const stop = useMutation<StopVTPMInstanceResponse, { id: string; force?: boolean }>(
    (params: { id: string; force?: boolean }): Promise<ApiResponse<StopVTPMInstanceResponse>> =>
      service.stop(params.id, params.force)
  );

  const getStatus = useMutation<GetVTPMInstanceStatusResponse, string>(
    (id: string): Promise<ApiResponse<GetVTPMInstanceStatusResponse>> =>
      service.getStatus(id)
  );

  const getEKCert = useMutation<GetVTPMInstanceEKCertResponse, { id: string; format?: 'pem' | 'der' }>(
    (params: { id: string; format?: 'pem' | 'der' }): Promise<ApiResponse<GetVTPMInstanceEKCertResponse>> =>
      service.getEKCert(params.id, params.format)
  );

  const getEKFingerprint = useMutation<GetVTPMInstanceEKFingerprintResponse, { id: string; algorithm?: 'sha256' | 'sha384' | 'sha512' }>(
    (params: { id: string; algorithm?: 'sha256' | 'sha384' | 'sha512' }): Promise<ApiResponse<GetVTPMInstanceEKFingerprintResponse>> =>
      service.getEKFingerprint(params.id, params.algorithm)
  );

  return {
    service,
    create,
    deleteInstance,
    start,
    stop,
    getStatus,
    getEKCert,
    getEKFingerprint,
  };
}

/**
 * Options for the useVTPMInstanceList hook
 */
export interface UseVTPMInstanceListOptions {
  /** Whether the query should be enabled */
  enabled?: boolean;
  /** Interval in milliseconds to automatically refetch data */
  refetchInterval?: number;
  /** Filter parameters */
  filters?: ListVTPMInstancesRequest;
}

/**
 * Hook for listing vTPM instances with automatic data fetching
 *
 * Provides a declarative way to fetch and display vTPM instances with
 * automatic state management for loading, error, and data states.
 *
 * @param options - Configuration options
 * @returns Query result with instances data and state
 *
 * @example
 * ```tsx
 * function VTPMInstanceList() {
 *   const { data, isLoading, error, refetch } = useVTPMInstanceList({
 *     filters: { isRunning: true },
 *     refetchInterval: 10000,
 *   });
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <ul>
 *       {data?.instances.map(instance => (
 *         <li key={instance.id}>
 *           {instance.id} - {instance.status}
 *         </li>
 *       ))}
 *     </ul>
 *   );
 * }
 * ```
 */
export function useVTPMInstanceList(
  options?: UseVTPMInstanceListOptions
): UseApiResult<ListVTPMInstancesResponse> {
  const client = usePlatformClient();
  const service = client.vtpm;

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

  return useApi<ListVTPMInstancesResponse>(
    () => service.list(options?.filters),
    [
      options?.filters?.page,
      options?.filters?.pageSize,
      options?.filters?.isRunning,
      options?.filters?.status,
      options?.filters?.profileId,
    ],
    Object.keys(apiOptions).length > 0 ? apiOptions : undefined
  );
}
