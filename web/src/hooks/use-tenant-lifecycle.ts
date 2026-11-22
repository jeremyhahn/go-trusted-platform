'use client';

import { useCallback, useRef, useState } from 'react';
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
/** A quota check answer with the resource and amount it answers. */
export interface QuotaCheckResult extends CheckQuotaResponse {
  resource: string;
  amount: number;
}

export interface UseTenantLifecycleResult {
  tenant: Tenant | null;
  dekStatus: TenantDEKStatus | null;
  quotaCheck: QuotaCheckResult | null;
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

// The REST handlers serialize TenantState through protojson, which emits the
// proto enum name (TENANT_STATE_SUSPENDED); the page compares the short name.
function normalizeTenant(t: Tenant): Tenant {
  return { ...t, state: String(t.state ?? '').replace(/^TENANT_STATE_/, '') as Tenant['state'] };
}

export function useTenantLifecycle(): UseTenantLifecycleResult {
  const service = useTenant();
  const [tenant, setTenant] = useState<Tenant | null>(null);
  const [dekStatus, setDEKStatus] = useState<TenantDEKStatus | null>(null);
  const [quotaCheck, setQuotaCheck] = useState<QuotaCheckResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const requireTenant = useCallback((): Tenant => {
    if (!tenant) throw new Error('Look up a tenant first');
    return tenant;
  }, [tenant]);

  // Each lookup takes a generation; a lookup superseded by a later one drops
  // its result, busy, error and notice updates, so an earlier lookup that
  // finishes last never becomes the target of remove, suspend or rotation.
  // Mutations capture the same generation when they start and drop their
  // selection, DEK and quota updates when a lookup has moved the selection
  // meanwhile, so a slow mutation of tenant A never re-selects A. run() drops
  // the busy, notice and error updates of a mutation once a lookup has moved
  // the selection, since that lookup owns them (#2023 F28).
  const lookupGen = useRef(0);

  /** Captures the selection generation; the returned check is true while it is unchanged. */
  const selection = useCallback(() => {
    const gen = lookupGen.current;
    return () => gen === lookupGen.current;
  }, []);

  const run = useCallback(
    async (action: () => Promise<string | null>) => {
      const current = selection();
      setBusy(true);
      setError(null);
      setNotice(null);
      try {
        const result = await action();
        if (current()) setNotice(result);
      } catch (err) {
        if (current()) setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        if (current()) setBusy(false);
      }
    },
    [selection]
  );

  const refresh = useCallback(
    async (id: string, current: () => boolean) => {
      const found = normalizeTenant(unwrap(await service.getTenant(id)).tenant);
      if (current()) setTenant(found);
    },
    [service]
  );

  const lookup = useCallback(
    async (name: string) => {
      const gen = ++lookupGen.current;
      const current = () => gen === lookupGen.current;
      setBusy(true);
      setError(null);
      setNotice(null);
      // Clear the previous selection first: a failed lookup must not leave
      // the earlier tenant as the target of delete, suspend or rotation.
      setTenant(null);
      setDEKStatus(null);
      setQuotaCheck(null);
      try {
        const found = unwrap(await service.getTenantByName(name)).tenant;
        if (current()) setTenant(normalizeTenant(found));
      } catch (err) {
        if (current()) setError(err instanceof Error ? err.message : 'Request failed');
      } finally {
        if (current()) setBusy(false);
      }
    },
    [service]
  );

  const update = useCallback(
    (displayName: string) =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        // TenantGRPCServer.UpdateTenant applies displayName only when it is
        // nonempty, so an empty one would be reported as saved but ignored.
        if (!displayName.trim()) throw new Error('Display name cannot be empty');
        const updated = unwrap(await service.updateTenant({ tenantId: t.id, displayName })).tenant;
        if (current()) setTenant(updated ? normalizeTenant(updated) : { ...t, displayName });
        return 'Tenant updated';
      }),
    [run, service, requireTenant, selection]
  );

  const remove = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        unwrap(await service.deleteTenant(t.id));
        if (current()) {
          setTenant(null);
          setDEKStatus(null);
        }
        return `Tenant ${t.name} deleted`;
      }),
    [run, service, requireTenant, selection]
  );

  const suspend = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        unwrap(await service.suspendTenant(t.id));
        await refresh(t.id, current);
        return 'Tenant suspended';
      }),
    [run, service, requireTenant, refresh, selection]
  );

  const resume = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        unwrap(await service.resumeTenant(t.id));
        await refresh(t.id, current);
        return 'Tenant resumed';
      }),
    [run, service, requireTenant, refresh, selection]
  );

  const updateQuotas = useCallback(
    (compute: ComputeQuota) =>
      run(async () => {
        const t = requireTenant();
        // UpdateQuotas replaces every limit of a supplied compute section, so
        // merge the change into the current limits to keep the others.
        const current = unwrap(await service.getQuotas(t.id)).compute ?? {};
        unwrap(await service.updateQuotas({ tenantId: t.id, compute: { ...current, ...compute } }));
        return 'Quotas updated';
      }),
    [run, service, requireTenant]
  );

  const checkQuota = useCallback(
    (resource: string, amount: number) =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        // Clear the earlier answer first: a failed check must not leave it
        // beside the new inputs as if it answered them.
        setQuotaCheck(null);
        const res = unwrap(await service.checkQuota({ tenantId: t.id, resource, amount }));
        if (current()) setQuotaCheck({ ...res, resource, amount });
        return null;
      }),
    [run, service, requireTenant, selection]
  );

  const sync = useCallback(
    () =>
      run(async () => {
        // Sync reports a failed run in status (HTTP 200), not as an RPC error.
        const res = unwrap(await service.syncTenants());
        if (res.status?.success === false) throw new Error(res.status.message || 'Tenant sync failed');
        return 'Tenant sync started';
      }),
    [run, service]
  );

  const loadDEKStatus = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        const status = unwrap(await service.getDEKStatus(t.id)).dekStatus;
        if (current()) setDEKStatus(status);
        return null;
      }),
    [run, service, requireTenant, selection]
  );

  const rotateDEK = useCallback(
    () =>
      run(async () => {
        const t = requireTenant();
        const current = selection();
        const rotated = unwrap(await service.rotateDEK({ tenantId: t.id }));
        const status = unwrap(await service.getDEKStatus(t.id)).dekStatus;
        if (current()) setDEKStatus(status);
        return `DEK rotated to version ${rotated.newVersion}`;
      }),
    [run, service, requireTenant, selection]
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
