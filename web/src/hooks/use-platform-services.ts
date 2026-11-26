'use client';

/**
 * Platform daemon services hook: ListServices, GetServiceStatus and the
 * StartService, StopService and RestartService actions (#2047).
 *
 * The hook calls the SDK PlatformService (listServices, getServiceStatus,
 * startService, stopService, restartService) on the mounted client.
 */

import { useMemo } from 'react';
import { usePlatform } from 'trusted-platform-sdk';

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
  const platform = usePlatform();
  return useMemo(
    () => ({
      listServices: () => platform.listServices(),
      getService: (name: string) => platform.getServiceStatus(name),
      act: (name: string, action: ServiceAction) =>
        action === 'start'
          ? platform.startService(name)
          : action === 'stop'
            ? platform.stopService(name)
            : platform.restartService(name),
    }),
    [platform]
  );
}
