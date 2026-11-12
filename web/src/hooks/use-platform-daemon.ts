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

  // Every request in flight, by key. Each request adds its key on start and
  // removes exactly one occurrence on completion, so an overlapping request
  // never clears another request's pending state.
  const [active, setActive] = React.useState<string[]>([]);

  /**
   * Run a call, adding `key` to the active requests until it settles;
   * throws on failure.
   */
  const run = React.useCallback(
    async <T,>(key: string, call: () => Promise<ApiResponse<T>>): Promise<T | undefined> => {
      setActive((a) => [...a, key]);
      try {
        const res = await call();
        if (!res.success) {
          throw new Error(res.error?.message ?? "Request failed");
        }
        return res.data;
      } finally {
        setActive((a) => {
          const i = a.indexOf(key);
          return i < 0 ? a : [...a.slice(0, i), ...a.slice(i + 1)];
        });
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
      // A failed lifecycle call can still change server state (a restart can
      // stop and then fail to start), so the list is re-read either way.
      try {
        return await run(`${action}:${name}`, call);
      } finally {
        services.refetch();
      }
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
    /** Whether a request under `key` is in flight. */
    isPending: (key: string) => active.includes(key),
    /** Whether any start, stop or restart is in flight. */
    lifecyclePending: active.some((k) => /^(start|stop|restart):/.test(k)),
    reloadConfig,
    serviceAction,
    getServiceStatus,
  };
}
