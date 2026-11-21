'use client';

/**
 * useTenantState — GetTenantByName, SuspendTenant and ResumeTenant on the SDK
 * TenantService (#2067): find a tenant by name, then suspend or resume it.
 */

import { useMemo } from 'react';
import { useTenant } from 'trusted-platform-sdk';

export function useTenantState() {
  const tenant = useTenant();
  return useMemo(
    () => ({
      getByName: (name: string) => tenant.getTenantByName(name),
      suspend: (id: string) => tenant.suspendTenant(id),
      resume: (id: string) => tenant.resumeTenant(id),
    }),
    [tenant]
  );
}

/** "TENANT_STATE_SUSPENDED" or "SUSPENDED" -> "SUSPENDED"; "" or undefined -> "UNKNOWN". */
export function tenantStateLabel(state: string | undefined): string {
  if (!state) return 'UNKNOWN';
  const label = state.startsWith('TENANT_STATE_') ? state.slice('TENANT_STATE_'.length) : state;
  return label || 'UNKNOWN';
}
