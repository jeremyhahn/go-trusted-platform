'use client';

/**
 * useTenantBarrier reads and drives a tenant's barrier. The SDK has no barrier
 * methods on main yet, so the hook goes through the platform API client on the
 * paths the server serves: GET /v1/tenants/{id}/barrier and
 * POST /v1/tenants/{id}/barrier/init|unseal|seal (#2067). Each call answers the
 * SDK's ApiResponse `{ success, data?, error? }`. A per-tenant barrier
 * initializes with the operator's passphrase and takes no Shamir split: the
 * server refuses a threshold or share count and an empty passphrase, so init
 * sends only `{ passphrase }`. The passphrase is never stored.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

export interface TenantBarrierStatus {
  tenantId?: string;
  sealed?: boolean;
  initialized?: boolean;
  strategy?: string;
  hardwareBacked?: boolean;
}

export function useTenantBarrier() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    const base = (id: string) => `/v1/tenants/${encodeURIComponent(id)}/barrier`;
    return {
      getStatus: (id: string) => api.get<{ barrierStatus?: TenantBarrierStatus }>(base(id)),
      init: (id: string, passphrase: string) => api.post(`${base(id)}/init`, { passphrase }),
      unseal: (id: string, key: string) => api.post(`${base(id)}/unseal`, { key }),
      seal: (id: string) => api.post(`${base(id)}/seal`, {}),
    };
  }, [client]);
}
