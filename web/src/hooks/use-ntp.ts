"use client";

/**
 * NTP hook: GetStatus, ListSources and Step (docs/ntp/api.md).
 *
 * Calls the platform's API client directly on the three NTP routes, so the
 * page works against an SDK build that predates `PlatformClient.ntp`.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** Node clock synchronisation status (protojson, lowerCamelCase). */
export interface NTPStatus {
  synced: boolean;
  stratum: number;
  leapStatus: string;
  offsetSeconds: number;
  rootDispersion: number;
  rootDelay: number;
  /** Seconds since the epoch; 0 means never synced. */
  lastSyncUnix: number | string;
  mode: string;
  referenceId: string;
  referenceName: string;
  sourcesReachable: number;
  sourcesTotal: number;
  anomaly: boolean;
  anomalyReason: string;
}

/** One configured time source. */
export interface NTPSource {
  address: string;
  mode: string;
  state: string;
  stratum: number;
  pollSeconds: number;
  reach: number;
  lastRxSeconds: number | string;
  offsetSeconds: number;
  reachable: boolean;
}

export interface NTPStatusResponse {
  status: NTPStatus;
}

export interface NTPSourcesResponse {
  sources: NTPSource[];
}

const NTP_BASE = "/v1/ntp";

export function useNTP() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      getStatus: () => api.get<NTPStatusResponse>(`${NTP_BASE}/status`),
      listSources: () => api.get<NTPSourcesResponse>(`${NTP_BASE}/sources`),
      step: () => api.post<NTPStatusResponse>(`${NTP_BASE}/step`),
    };
  }, [client]);
}
