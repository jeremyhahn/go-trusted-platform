"use client";

import * as React from "react";
import { useApi, usePlatform } from "trusted-platform-sdk";
import type {
  ApiResponse,
  DaemonServiceActionResponse,
  DaemonServiceInfo,
} from "trusted-platform-sdk";

/** A service lifecycle action the daemon serves over REST. */
export type DaemonServiceAction = "start" | "stop" | "restart";

/**
 * Daemon status, version, configuration and service lifecycle for the
 * platform services page (#1752).
 */
export function usePlatformDaemon() {
  const platform = usePlatform();

  const status = useApi(() => platform.getStatus(), []);
  const version = useApi(() => platform.getVersion(), []);
  const config = useApi(() => platform.getConfig(), []);
  const services = useApi(() => platform.listServices(), []);

  const [pending, setPending] = React.useState<string | null>(null);

  /** Run a call, tracking it as pending under `key`; throws on failure. */
  const run = React.useCallback(
    async <T,>(key: string, call: () => Promise<ApiResponse<T>>): Promise<T | undefined> => {
      setPending(key);
      try {
        const res = await call();
        if (!res.success) {
          throw new Error(res.error?.message ?? "Request failed");
        }
        return res.data;
      } finally {
        setPending(null);
      }
    },
    []
  );

  const reloadConfig = React.useCallback(async () => {
    const data = await run("reload", () => platform.reloadConfig());
    config.refetch();
    return data;
  }, [run, platform, config]);

  const serviceAction = React.useCallback(
    async (name: string, action: DaemonServiceAction): Promise<DaemonServiceActionResponse | undefined> => {
      const call =
        action === "start"
          ? () => platform.startService(name)
          : action === "stop"
            ? () => platform.stopService(name)
            : () => platform.restartService(name);
      const data = await run(`${action}:${name}`, call);
      services.refetch();
      return data;
    },
    [run, platform, services]
  );

  const getServiceStatus = React.useCallback(
    (name: string): Promise<DaemonServiceInfo | undefined> =>
      run(`status:${name}`, () => platform.getServiceStatus(name)),
    [run, platform]
  );

  return {
    status,
    version,
    config,
    services,
    pending,
    reloadConfig,
    serviceAction,
    getServiceStatus,
  };
}
