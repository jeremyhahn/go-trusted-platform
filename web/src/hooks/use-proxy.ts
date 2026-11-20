"use client";

/**
 * Reverse-proxy hook: the 14 ProxyService operations (#2061) through the
 * SDK's `PlatformClient.proxy` service, on /api/v1/proxy.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";
import type { ProxyBackend, ProxyPool, ProxyRoute } from "trusted-platform-sdk";

export type { ProxyBackend, ProxyPool, ProxyRoute };

/**
 * Parse a backend list typed into a form: URLs separated by commas or new
 * lines, each with an optional `=weight` suffix (default 1).
 */
export function parseBackends(text: string): ProxyBackend[] {
  return text
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0)
    .map((s) => {
      const m = /^(.*)=(\d+)$/.exec(s);
      if (m) {
        return { url: m[1].trim(), weight: Number(m[2]) };
      }
      return { url: s, weight: 1 };
    });
}

/** Render a backend list back into the form's text. */
export function formatBackends(backends: ProxyBackend[] | undefined): string {
  return (backends ?? [])
    .map((b) => (b.weight && b.weight !== 1 ? `${b.url}=${b.weight}` : b.url))
    .join("\n");
}

export function useProxy() {
  const client = usePlatformClient();
  return useMemo(() => {
    const svc = client.proxy;
    return {
      listRoutes: () => svc.listRoutes(),
      createRoute: (route: ProxyRoute) => svc.createRoute(route),
      getRoute: (id: string) => svc.getRoute(id),
      updateRoute: (id: string, route: Partial<ProxyRoute>) => svc.updateRoute(id, route),
      deleteRoute: (id: string) => svc.deleteRoute(id),
      listPools: () => svc.listPools(),
      createPool: (pool: ProxyPool) => svc.createPool(pool),
      getPool: (id: string) => svc.getPool(id),
      updatePool: (id: string, pool: Partial<ProxyPool>) => svc.updatePool(id, pool),
      deletePool: (id: string) => svc.deletePool(id),
      getConfig: () => svc.getProxyConfig(),
      reloadConfig: () => svc.reloadProxyConfig(),
      getStatus: () => svc.getStatus(),
      getZoneMatrix: () => svc.getZoneMatrix(),
    };
  }, [client]);
}
