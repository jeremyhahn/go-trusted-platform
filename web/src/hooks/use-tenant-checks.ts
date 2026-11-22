'use client';

/**
 * Tenant checks hook: CheckQuota, GetTenantDEKStatus and Sync (#2067).
 *
 * CheckQuota and GetTenantDEKStatus go through the platform's API client on
 * the paths the control plane serves (POST /v1/tenants/{id}/quota-check and
 * GET /v1/tenants/{id}/dek) until the SDK's TenantService paths are fixed
 * (it calls /quotas/check and /dek/status, which are not served). Sync goes
 * through the SDK's TenantService.syncTenants.
 */

import { useMemo } from 'react';
import { usePlatformClient, useTenant } from 'trusted-platform-sdk';

/** The CheckQuota answer: a refusal by quota is `available: false`, not an error. */
export interface QuotaCheckResult {
  tenantId?: string;
  resource?: string;
  amount?: number | string;
  available?: boolean;
  message?: string;
}

/** A tenant's data encryption key status (protojson; uint64 fields arrive as strings). */
export interface TenantDEKStatus {
  tenantId?: string;
  path?: string;
  version?: number | string;
  algorithm?: string;
  status?: string;
  isDefault?: boolean;
  createdAt?: string;
  rotatedAt?: string;
  usageCount?: number | string;
  bytesUsed?: number | string;
  maxUsageCount?: number | string;
  maxBytesUsed?: number | string;
  warningPercent?: number;
  usagePercent?: number;
  needsRotation?: boolean;
}

/** The resource types the quota service accepts (pkg/tenant/quota/types.go). */
export const QUOTA_RESOURCES = [
  'vms',
  'containers',
  'vcpus',
  'memory',
  'disk',
  'bridges',
  'ports',
  'bandwidth',
  'volumes',
  'snapshots',
] as const;

export function useTenantChecks() {
  const client = usePlatformClient();
  const tenant = useTenant();
  return useMemo(() => {
    const api = client.getApiClient();
    const base = (id: string) => `/v1/tenants/${encodeURIComponent(id)}`;
    return {
      checkQuota: (id: string, resource: string, amount: number) =>
        api.post<QuotaCheckResult>(`${base(id)}/quota-check`, { resource, amount }),
      getDEKStatus: (id: string) => api.get<{ dekStatus?: TenantDEKStatus }>(`${base(id)}/dek`),
      sync: () => tenant.syncTenants(),
    };
  }, [client, tenant]);
}
