'use client';

import { useCallback, useState } from 'react';
import { useTenant } from 'trusted-platform-sdk';
import type {
  ApiResponse,
  CheckQuotaResponse,
  ComputeQuota,
  Tenant,
  TenantDEKStatus,
} from 'trusted-platform-sdk';

/**
 * Drives the TenantService lifecycle, quota, sync and DEK operations for
 * the tenant lifecycle page (#1758).
 */
export interface UseTenantLifecycleResult {
  tenant: Tenant | null;
  dekStatus: TenantDEKStatus | null;
  quotaCheck: CheckQuotaResponse | null;
  busy: boolean;
  error: string | null;
  notice: string | null;
  lookup: (name: string) => Promise<void>;
  update: (displayName: string) => Promise<void>;
  remove: () => Promise<void>;
  suspend: () => Promise<void>;
  resume: () => Promise<void>;
  updateQuotas: (compute: ComputeQuota) => Promise<void>;
  checkQuota: (resource: string, amount: number) => Promise<void>;
  sync: () => Promise<void>;
  rotateDEK: () => Promise<void>;
  loadDEKStatus: () => Promise<void>;
}

function unwrap<T>(response: ApiResponse<T>): T {
  if (!response.success || response.data === undefined) {
    throw new Error(response.error?.message ?? 'Request failed');
  }
  return response.data;
}

export function useTenantLifecycle(): UseTenantLifecycleResult {
  const service = useTenant();
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [dekStatus, setDEKStatus] = useState<TenantDEKStatus | null>(null);
  const [quotaCheck, setQuotaCheck] = useState<CheckQuotaResponse | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const run = useCallback(async (action: () => Promise<string | null>) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      setNotice(await action());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Request failed');
    } finally {
      setBusy(false);
    }
  }, []);

  const requireTenant = useCallback((): Tenant => {
    if (!tenant) throw new Error('Look up a tenant first');
    return tenant;
  }, [tenant]);

  const refresh = useCallback(
    async (id: string) => {
      setTenant(unwrap(await service.getTenant(id)).tenant);
    },
    [service]
  );

  const lookup = useCallback(
    (name: string) =>
      run(async () => {
        const found = unwrap(await service.getTenantByName(name)).tenant;
        setTenant(found);
        setDEKStatus(null);
        setQuotaCheck(null);
        return null;
      }),
    [run, service]
  );

  const update = useCallback(
    (displayName: string) =>
      run(async () => {
        const t = requireTenant();
        const updated = unwrap(await service.updateTenant({ tenantId: t.id, displayName })).tenant;
        setTenant(updated ?? { ...t, displayName });
        return 'Tenant updated';
      }),
    [run, service, requireTenant]
  );

  const remove = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        unwrap(await service.deleteTenant(t.id));
        setTenant(null);
        setDEKStatus(null);
        return `Tenant ${t.name} deleted`;
      }),
    [run, service, requireTenant]
  );

  const suspend = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        unwrap(await service.suspendTenant(t.id));
        await refresh(t.id);
        return 'Tenant suspended';
      }),
    [run, service, requireTenant, refresh]
  );

  const resume = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        unwrap(await service.resumeTenant(t.id));
        await refresh(t.id);
        return 'Tenant resumed';
      }),
    [run, service, requireTenant, refresh]
  );

  const updateQuotas = useCallback(
    (compute: ComputeQuota) =>
      run(async () => {
        const t = requireTenant();
        unwrap(await service.updateQuotas({ tenantId: t.id, compute }));
        return 'Quotas updated';
      }),
    [run, service, requireTenant]
  );

  const checkQuota = useCallback(
    (resource: string, amount: number) =>
      run(async () => {
        const t = requireTenant();
        setQuotaCheck(unwrap(await service.checkQuota({ tenantId: t.id, resource, amount })));
        return null;
      }),
    [run, service, requireTenant]
  );

  const sync = useCallback(
    () =>
      run(async () => {
        unwrap(await service.syncTenants());
        return 'Tenant sync started';
      }),
    [run, service]
  );

  const loadDEKStatus = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        setDEKStatus(unwrap(await service.getDEKStatus(t.id)).dekStatus);
        return null;
      }),
    [run, service, requireTenant]
  );

  const rotateDEK = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const rotated = unwrap(await service.rotateDEK({ tenantId: t.id }));
        setDEKStatus(unwrap(await service.getDEKStatus(t.id)).dekStatus);
        return `DEK rotated to version ${rotated.newVersion}`;
      }),
    [run, service, requireTenant]
  );

  return {
    tenant,
    dekStatus,
    quotaCheck,
    busy,
    error,
    notice,
    lookup,
    update,
    remove,
    suspend,
    resume,
    updateQuotas,
    checkQuota,
    sync,
    rotateDEK,
    loadDEKStatus,
  };
}
