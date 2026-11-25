"use client";

/**
 * Capability gate: what this server offers (GET /api/v1/capabilities).
 *
 * `useCapabilities().capability(op)` answers whether one operation, named by
 * the server's op string `"METHOD /api/v1/path"`, is enabled. Every hook on
 * one PlatformClient shares one request. The gate fails closed: while the
 * list loads, when it cannot be read, and for an op the server does not
 * list, the op is disabled with a reason (#2033 item 4, #2058).
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { usePlatformClient, type Capability, type PlatformClient } from "trusted-platform-sdk";

export interface CapabilityAnswer {
  enabled: boolean;
  reason?: string;
}

export interface UseCapabilitiesResult {
  loading: boolean;
  error: unknown;
  capability(op: string): CapabilityAnswer;
}

export const CAPABILITIES_LOADING_REASON = "checking server capabilities";
export const CAPABILITIES_UNAVAILABLE_REASON = "server capabilities unavailable";
export const CAPABILITY_NOT_OFFERED_REASON = "not offered by this server";

type CapabilityMap = Map<string, Capability>;

const cache = new WeakMap<PlatformClient, Promise<CapabilityMap>>();
// The answers already read, so a control that mounts after the read settled
// (a table row's Gated button) starts enabled instead of passing through
// "checking server capabilities" for a tick.
const settled = new WeakMap<PlatformClient, CapabilityMap>();

function loadCapabilities(client: PlatformClient): Promise<CapabilityMap> {
  let pending = cache.get(client);
  if (!pending) {
    pending = client.capabilities.list().then((res) => {
      if (!res.success || !res.data) {
        throw new Error(res.error?.message ?? CAPABILITIES_UNAVAILABLE_REASON);
      }
      const caps: CapabilityMap = new Map((res.data.capabilities ?? []).map((c) => [c.op, c]));
      settled.set(client, caps);
      return caps;
    });
    // A failed read is not cached, so a later mount asks again.
    pending.catch(() => {
      if (cache.get(client) === pending) {
        cache.delete(client);
      }
    });
    cache.set(client, pending);
  }
  return pending;
}

/** The answer for one client; a state for another client reads as loading. */
interface Loaded {
  client: PlatformClient;
  error: unknown;
  caps: CapabilityMap | undefined;
}

export function useCapabilities(): UseCapabilitiesResult {
  const client = usePlatformClient();
  const [loaded, setLoaded] = useState<Loaded | undefined>(undefined);

  useEffect(() => {
    let live = true;
    loadCapabilities(client).then(
      (caps) => {
        if (live) setLoaded({ client, error: undefined, caps });
      },
      (error: unknown) => {
        if (live) {
          setLoaded({ client, error: error ?? new Error(CAPABILITIES_UNAVAILABLE_REASON), caps: undefined });
        }
      }
    );
    return () => {
      live = false;
    };
  }, [client]);

  const known = settled.get(client);
  const current = useMemo<Loaded | undefined>(() => {
    if (loaded?.client === client) return loaded;
    return known ? { client, error: undefined, caps: known } : undefined;
  }, [loaded, client, known]);

  const capability = useCallback(
    (op: string): CapabilityAnswer => {
      if (!current) {
        return { enabled: false, reason: CAPABILITIES_LOADING_REASON };
      }
      if (!current.caps) {
        return { enabled: false, reason: CAPABILITIES_UNAVAILABLE_REASON };
      }
      const cap = current.caps.get(op);
      if (!cap) {
        return { enabled: false, reason: CAPABILITY_NOT_OFFERED_REASON };
      }
      return cap.reason ? { enabled: cap.enabled, reason: cap.reason } : { enabled: cap.enabled };
    },
    [current]
  );

  return { loading: !current, error: current?.error, capability };
}
