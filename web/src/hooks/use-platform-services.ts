'use client';

/**
 * Platform daemon services hook: ListServices, GetServiceStatus and the
 * StartService, StopService and RestartService actions (#2047).
 *
 * The daemon services are reached on the API client at the served
 * `/v1/platform/services` routes until the SDK PlatformService has them.
 */

import { useMemo } from 'react';
import { usePlatformClient } from 'trusted-platform-sdk';

export type ServiceAction = 'start' | 'stop' | 'restart';

/** One daemon service as the server reports it (snake_case JSON). */
export interface PlatformServiceInfo {
  name: string;
  status?: string;
  started_at?: string;
  uptime?: string;
  start_count?: number;
  stop_count?: number;
  last_error?: string;
}

export interface PlatformServiceList {
  services?: PlatformServiceInfo[];
  count?: number;
  timestamp?: number;
}

export interface ServiceActionResult {
  service?: string;
  action?: string;
  success?: boolean;
  message?: string;
}

export function usePlatformServices() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    const one = (name: string) => `/v1/platform/services/${encodeURIComponent(name)}`;
    return {
      listServices: () => api.get<PlatformServiceList>('/v1/platform/services'),
      getService: (name: string) => api.get<PlatformServiceInfo>(one(name)),
      act: (name: string, action: ServiceAction) => api.post<ServiceActionResult>(`${one(name)}/${action}`),
    };
  }, [client]);
}
