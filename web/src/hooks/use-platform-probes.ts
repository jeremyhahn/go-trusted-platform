"use client";

/**
 * Platform probes hook: GetStatus, Liveness and Readiness (#2047).
 *
 * Calls the platform's API client directly on the three routes, because the
 * SDK PlatformService has no method for them yet.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** The flat snake_case body of GET /platform/status (types.go StatusResponse). */
export interface PlatformStatusWire {
  status?: string;
  version?: string;
  go_version?: string;
  timestamp?: number;
  system?: {
    os?: string;
    arch?: string;
    num_cpus?: number;
    total_memory_mb?: number;
    available_memory_mb?: number;
    uptime?: string;
  };
}

/** The body of GET /platform/liveness and /platform/readiness (probes.go ProbeResponse). */
export interface ProbeWire {
  alive?: boolean;
  ready?: boolean;
  status?: string;
  timestamp?: string;
}

export interface PlatformProbes {
  status: PlatformStatusWire | null;
  liveness: ProbeWire | null;
  readiness: ProbeWire | null;
}

export const PLATFORM_PROBE_PATHS = {
  status: "/v1/platform/status",
  liveness: "/v1/platform/liveness",
  readiness: "/v1/platform/readiness",
} as const;

type ProbeKey = keyof PlatformProbes;
type ProbeErrors = Partial<Record<ProbeKey, string>>;

const EMPTY: PlatformProbes = { status: null, liveness: null, readiness: null };

/** Reads the three in parallel; each refusal lands in errors[key] as `HTTP <status>: <message>`, the others still show. */
export function usePlatformProbes(): {
  probes: PlatformProbes;
  errors: ProbeErrors;
  isLoading: boolean;
  refetch: () => Promise<void>;
} {
  const client = usePlatformClient();
  const api = useMemo(() => client.getApiClient(), [client]);
  const [probes, setProbes] = useState<PlatformProbes>(EMPTY);
  const [errors, setErrors] = useState<ProbeErrors>({});
  const [isLoading, setIsLoading] = useState(true);

  const read = useCallback(async () => {
    setIsLoading(true);
    const keys = Object.keys(PLATFORM_PROBE_PATHS) as ProbeKey[];
    const results = await Promise.all(
      keys.map(async (key): Promise<{ key: ProbeKey; data: unknown; error?: string }> => {
        try {
          const res = await api.get<unknown>(PLATFORM_PROBE_PATHS[key]);
          if (res.error) {
            return {
              key,
              data: null,
              error:
                res.error.status !== undefined
                  ? `HTTP ${res.error.status}: ${res.error.message}`
                  : res.error.message,
            };
          }
          return { key, data: res.data ?? {} };
        } catch (err) {
          return { key, data: null, error: err instanceof Error ? err.message : String(err) };
        }
      })
    );
    const next: PlatformProbes = { ...EMPTY };
    const nextErrors: ProbeErrors = {};
    for (const r of results) {
      if (r.error !== undefined) {
        nextErrors[r.key] = r.error;
      } else {
        (next as Record<ProbeKey, unknown>)[r.key] = r.data;
      }
    }
    setProbes(next);
    setErrors(nextErrors);
    setIsLoading(false);
  }, [api]);

  useEffect(() => {
    void read();
  }, [read]);

  return { probes, errors, isLoading, refetch: read };
}
