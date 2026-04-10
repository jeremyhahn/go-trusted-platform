/**
 * Provisioning Session React Hook
 *
 * Provides React hooks for provisioning session management with built-in
 * state management for queries and mutations.
 *
 * @packageDocumentation
 */

import type {
  ProvisioningSession,
  FulfillSessionRequest,
} from '../../types/device.js';
import type { ApiResponse } from '../../types/api.js';
import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import type { UseMutationResult } from './use-mutation.js';
import type { UseApiResult } from './use-api.js';

/**
 * Result returned by the useProvisioningSessions hook
 */
export interface UseProvisioningSessionResult {
  /** List of provisioning sessions */
  sessions: ProvisioningSession[];

  /** Whether the initial fetch is in progress */
  isLoading: boolean;

  /** The error if the fetch failed, or null if successful */
  error: Error | null;

  /** Manually trigger a refetch */
  refetch: () => void;

  /** Mutation for fulfilling a provisioning session */
  fulfill: UseMutationResult<void, FulfillSessionRequest>;
}

/**
 * Hook for provisioning session management
 *
 * Provides access to all provisioning sessions with automatic data fetching
 * and a mutation for fulfilling pending sessions by assigning a profile.
 *
 * @returns Object with session list, query state, and mutation helpers
 *
 * @example
 * ```tsx
 * function SessionDashboard() {
 *   const { sessions, isLoading, error, fulfill } = useProvisioningSessions();
 *
 *   const handleFulfill = (sessionId: string, profileId: number) => {
 *     fulfill.mutate({ sessionId, profileId });
 *   };
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <ul>
 *       {sessions.map(session => (
 *         <li key={session.id}>
 *           {session.id} — fulfilled: {String(session.fulfilled)}
 *           {!session.fulfilled && (
 *             <button onClick={() => handleFulfill(session.id, 1)}>
 *               Fulfill
 *             </button>
 *           )}
 *         </li>
 *       ))}
 *     </ul>
 *   );
 * }
 * ```
 */
export function useProvisioningSessions(): UseProvisioningSessionResult {
  const client = usePlatformClient();
  const service = client.device;

  const listResult: UseApiResult<ProvisioningSession[]> = useApi<ProvisioningSession[]>(
    () => service.listProvisioningSessions(),
    []
  );

  const fulfill = useMutation<void, FulfillSessionRequest>(
    (request: FulfillSessionRequest): Promise<ApiResponse<void>> =>
      service.fulfillProvisioningSession(request)
  );

  return {
    sessions: listResult.data ?? [],
    isLoading: listResult.isLoading,
    error: listResult.error ?? null,
    refetch: () => { void listResult.refetch(); },
    fulfill,
  };
}
