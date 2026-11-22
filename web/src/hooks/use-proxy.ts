"use client";

/**
 * Proxy hook: the ProxyService on `client.proxy`.
 *
 * It reaches the fourteen proxy operations served under `/api/v1/proxy`
 * (list/get/create/update/delete routes and pools, config, reload, status
 * and the zone matrix). Route and pool writes send `{ route }` / `{ pool }`
 * bodies; `version` is a uint64 carried as a decimal string.
 */

import { usePlatformClient, type ProxyPool, type ProxyRoute, type ProxyService } from "trusted-platform-sdk";

/** The ProxyService of the current platform client (stable per client). */
export function useProxy(): ProxyService {
  const client = usePlatformClient();
  return client.proxy;
}

/** Display form of a route's match: hosts (or '*') then the path prefix (or '/'). */
export function proxyRouteMatch(route: ProxyRoute): string {
  const hosts = (route.hosts ?? []).filter((h) => h !== "");
  const hostPart = hosts.length > 0 ? hosts.join(", ") : "*";
  return `${hostPart} ${route.pathPrefix || "/"}`;
}

/** Display form of a pool: its backend count and balancer. */
export function proxyPoolSummary(pool: ProxyPool): string {
  const n = pool.backends?.length ?? 0;
  return `${n} ${n === 1 ? "backend" : "backends"}, ${pool.balancer || "round-robin"}`;
}
