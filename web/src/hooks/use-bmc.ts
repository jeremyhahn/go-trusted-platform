"use client";

import * as React from "react";

// The wire shapes mirror the SDK's BMCService types (sdk/javascript
// src/services/bmc-service.ts). They are declared here so the console does
// not need an SDK rebuild to pick them up, as with use-reported-gateways.
export interface BMCPowerStatus {
  state: string;
}
export interface BMCBootDevice {
  device: string;
  persistent?: boolean;
}
export interface BMCVirtualMediaStatus {
  inserted: boolean;
  image?: string;
}
export interface BMCSensor {
  name: string;
  reading: number;
  units?: string;
  status?: string;
}
export interface BMCSystemInfo {
  manufacturer?: string;
  model?: string;
  serial_number?: string;
  bios_version?: string;
  bmc_firmware?: string;
}
export interface BMCProvisionStatus {
  state: string;
  message?: string;
}
export interface BMCWebCertificate {
  certificate: string;
  subject?: string;
  not_after?: string;
}

/**
 * The read side of one BMC profile, each part fetched on its own so a BMC
 * that cannot answer one call (no sensors, no web certificate) still shows
 * the rest (#1736).
 */
export interface BMCState {
  power: BMCPowerStatus | null;
  bootDevice: BMCBootDevice | null;
  virtualMedia: BMCVirtualMediaStatus | null;
  sensors: BMCSensor[] | null;
  systemInfo: BMCSystemInfo | null;
  provisionStatus: BMCProvisionStatus | null;
  certificate: BMCWebCertificate | null;
}

export type BMCPart = keyof BMCState;

export interface UseBMCResult extends BMCState {
  isLoading: boolean;
  /** The error of each part that failed to load, by part */
  errors: Partial<Record<BMCPart, string>>;
  refetch: () => Promise<void>;
  setBootDevice: (request: BMCBootDevice) => Promise<void>;
  mountISO: (image: string) => Promise<void>;
  unmountISO: () => Promise<void>;
  provision: () => Promise<void>;
}

const EMPTY: BMCState = {
  power: null,
  bootDevice: null,
  virtualMedia: null,
  sensors: null,
  systemInfo: null,
  provisionStatus: null,
  certificate: null,
};

/** bmcUrl is the console path of one BMC operation */
export function bmcUrl(profileID: string, op: string): string {
  return `/api/v1/bmc/${encodeURIComponent(profileID)}/${op}`;
}

/** Unwraps the platform envelope, or throws its error message */
async function call<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    credentials: "include",
    ...init,
    headers: init?.body ? { "Content-Type": "application/json" } : undefined,
  });
  const text = await res.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  const envelope = (body ?? {}) as { payload?: unknown; error?: string; message?: string };
  if (!res.ok) {
    throw new Error(envelope.error || envelope.message || `HTTP ${res.status}`);
  }
  return (envelope.payload ?? body) as T;
}

/**
 * useBMC reads and drives one BMC profile through the
 * `/api/v1/bmc/{profileID}/...` routes.
 */
export function useBMC(profileID: string): UseBMCResult {
  const [loaded, setLoaded] = React.useState<LoadedBMC | null>(null);

  const apply = React.useCallback((next: LoadedBMC) => setLoaded(next), []);

  React.useEffect(() => {
    if (!profileID) {
      return;
    }
    let cancelled = false;
    void loadBMC(profileID).then((next) => {
      if (!cancelled) {
        apply(next);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [profileID, apply]);

  const refetch = React.useCallback(async () => {
    if (profileID) {
      apply(await loadBMC(profileID));
    }
  }, [profileID, apply]);

  const mutate = React.useCallback(
    async (op: string, method: "POST" | "DELETE", body?: unknown) => {
      await call<unknown>(bmcUrl(profileID, op), {
        method,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      await refetch();
    },
    [profileID, refetch]
  );

  const current = loaded && loaded.profileID === profileID ? loaded : null;

  return {
    ...(current?.state ?? EMPTY),
    isLoading: current === null,
    errors: current?.errors ?? {},
    refetch,
    setBootDevice: (request) => mutate("boot-device", "POST", request),
    mountISO: (image) => mutate("virtual-media", "POST", { image }),
    unmountISO: () => mutate("virtual-media", "DELETE"),
    provision: () => mutate("provision", "POST", {}),
  };
}

interface LoadedBMC {
  profileID: string;
  state: BMCState;
  errors: Partial<Record<BMCPart, string>>;
}

/** loadBMC reads every part of one profile; a failed part is an error, not a throw */
async function loadBMC(profileID: string): Promise<LoadedBMC> {
  const parts: Array<[BMCPart, string, (v: unknown) => unknown]> = [
    ["power", "power", (v) => v],
    ["bootDevice", "boot-device", (v) => v],
    ["virtualMedia", "virtual-media", (v) => v],
    ["sensors", "sensors", (v) => (v as { sensors?: BMCSensor[] } | null)?.sensors ?? []],
    ["systemInfo", "system-info", (v) => v],
    ["provisionStatus", "provision", (v) => v],
    ["certificate", "cert", (v) => v],
  ];
  const results = await Promise.allSettled(
    parts.map(([, op, pick]) => call<unknown>(bmcUrl(profileID, op)).then(pick))
  );
  const state: BMCState = { ...EMPTY };
  const errors: Partial<Record<BMCPart, string>> = {};
  results.forEach((r, i) => {
    const part = parts[i][0];
    if (r.status === "fulfilled") {
      (state as unknown as Record<BMCPart, unknown>)[part] = r.value;
    } else {
      errors[part] = r.reason instanceof Error ? r.reason.message : String(r.reason);
    }
  });
  return { profileID, state, errors };
}
