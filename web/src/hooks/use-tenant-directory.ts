import { useMemo } from 'react';
import { useTenant } from 'trusted-platform-sdk';

/**
 * The tenant directory on the SDK's TenantService (#2067): ListTenants,
 * CreateTenant, UpdateTenant and DeleteTenant. Each call answers the SDK's
 * ApiResponse, so the caller shows a refusal's error message as the server
 * sent it.
 */
export function useTenantDirectory() {
  const tenant = useTenant();
  return useMemo(
    () => ({
      list: () => tenant.listTenants(),
      create: (name: string, displayName: string) => tenant.createTenant({ name, displayName }),
      rename: (id: string, displayName: string) => tenant.updateTenant({ tenantId: id, displayName }),
      remove: (id: string) => tenant.deleteTenant(id),
    }),
    [tenant]
  );
}
