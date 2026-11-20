'use client';

/**
 * IAM application detail hook (#2054).
 *
 * The REST wire shape differs from the SDK/proto declaration (#445): an
 * app may come back nested under `app` or flat, with camelCase or
 * snake_case keys, so the hook normalises it once for the page.
 */

import { useApi, useIAM } from 'trusted-platform-sdk';

/** An application as the detail page shows it. */
export interface AppDetail {
  name?: string;
  redirectUris: string[];
  grantTypes: string[];
  createdAt?: string;
}

interface AppWire {
  name?: string;
  redirect_uris?: string[];
  redirectUris?: string[];
  grant_types?: string[];
  grantTypes?: string[];
  created_at?: string;
  createdAt?: string;
}

/** Normalises the GetApp wire response. */
export function toAppDetail(raw: unknown): AppDetail | null {
  const wire = raw as (AppWire & { app?: AppWire }) | null | undefined;
  const a = wire?.app ?? wire ?? null;
  if (!a) return null;
  return {
    name: a.name,
    redirectUris: a.redirect_uris ?? a.redirectUris ?? [],
    grantTypes: a.grant_types ?? a.grantTypes ?? [],
    createdAt: a.created_at ?? a.createdAt,
  };
}

/** Loads one application by client ID for the tenant. */
export function useAppDetail(tenantId: string | null | undefined, clientId: string) {
  const iam = useIAM();
  const result = useApi(() => {
    if (!tenantId) return Promise.reject(new Error('No tenant ID'));
    return iam.getApp(tenantId, clientId);
  }, [tenantId, clientId]);
  return { ...result, app: toAppDetail(result.data) };
}
