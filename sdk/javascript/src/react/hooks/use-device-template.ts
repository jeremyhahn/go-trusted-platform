/**
 * Device Template React Hook
 *
 * Provides React hooks for device template management with built-in
 * state management for queries and mutations.
 *
 * @packageDocumentation
 */

import type {
  DeviceTemplate,
  DeviceProfile,
  CreateDeviceTemplateRequest,
  UpdateDeviceTemplateRequest,
  CreateProfileFromTemplateRequest,
} from '../../types/device.js';
import type { ApiResponse } from '../../types/api.js';
import { usePlatformClient } from '../context.js';
import { useMutation } from './use-mutation.js';
import { useApi } from './use-api.js';
import type { UseMutationResult } from './use-mutation.js';
import type { UseApiResult } from './use-api.js';

/**
 * Result returned by the useDeviceTemplates hook
 */
export interface UseDeviceTemplateResult {
  /** List of device templates */
  templates: DeviceTemplate[];

  /** Whether the initial fetch is in progress */
  isLoading: boolean;

  /** The error if the fetch failed, or null if successful */
  error: Error | null;

  /** Manually trigger a refetch */
  refetch: () => void;

  /** Mutation for creating a device template */
  create: UseMutationResult<DeviceTemplate, CreateDeviceTemplateRequest>;

  /** Mutation for updating a device template */
  update: UseMutationResult<DeviceTemplate, UpdateDeviceTemplateRequest>;

  /** Mutation for deleting a device template */
  remove: UseMutationResult<void, number>;

  /** Mutation for creating a profile from a template */
  createProfileFromTemplate: UseMutationResult<DeviceProfile, CreateProfileFromTemplateRequest>;
}

/**
 * Hook for device template management
 *
 * Provides access to device templates with automatic data fetching and
 * pre-configured mutations for creating, updating, and deleting templates.
 *
 * @param page - Page number for pagination
 * @param pageSize - Number of items per page
 * @returns Object with template list, query state, and mutation helpers
 *
 * @example
 * ```tsx
 * function TemplateManager() {
 *   const { templates, isLoading, error, create, remove } = useDeviceTemplates();
 *
 *   const handleCreate = () => {
 *     create.mutate({
 *       name: 'Edge Gateway Template',
 *       role: 'GATEWAY',
 *       description: 'Standard edge gateway configuration',
 *     });
 *   };
 *
 *   if (isLoading) return <Loading />;
 *   if (error) return <Error message={error.message} />;
 *
 *   return (
 *     <div>
 *       <button onClick={handleCreate} disabled={create.isLoading}>
 *         {create.isLoading ? 'Creating...' : 'Create Template'}
 *       </button>
 *       <ul>
 *         {templates.map(t => (
 *           <li key={t.id}>
 *             {t.name}
 *             <button onClick={() => remove.mutate(t.id)}>Delete</button>
 *           </li>
 *         ))}
 *       </ul>
 *     </div>
 *   );
 * }
 * ```
 */
export function useDeviceTemplates(
  page?: number,
  pageSize?: number
): UseDeviceTemplateResult {
  const client = usePlatformClient();
  const service = client.device;

  const listResult: UseApiResult<DeviceTemplate[]> = useApi<DeviceTemplate[]>(
    () => service.listTemplates(
      page !== undefined || pageSize !== undefined
        ? { ...(page !== undefined && { page }), ...(pageSize !== undefined && { pageSize }) }
        : undefined
    ),
    [page, pageSize]
  );

  const create = useMutation<DeviceTemplate, CreateDeviceTemplateRequest>(
    (request: CreateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> =>
      service.createTemplate(request)
  );

  const update = useMutation<DeviceTemplate, UpdateDeviceTemplateRequest>(
    (request: UpdateDeviceTemplateRequest): Promise<ApiResponse<DeviceTemplate>> =>
      service.updateTemplate(request)
  );

  const remove = useMutation<void, number>(
    (id: number): Promise<ApiResponse<void>> =>
      service.deleteTemplate(id)
  );

  const createProfileFromTemplate = useMutation<DeviceProfile, CreateProfileFromTemplateRequest>(
    (request: CreateProfileFromTemplateRequest): Promise<ApiResponse<DeviceProfile>> =>
      service.createProfileFromTemplate(request)
  );

  return {
    templates: listResult.data ?? [],
    isLoading: listResult.isLoading,
    error: listResult.error ?? null,
    refetch: () => { void listResult.refetch(); },
    create,
    update,
    remove,
    createProfileFromTemplate,
  };
}
