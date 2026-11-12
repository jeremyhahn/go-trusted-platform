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
/** VirtualMediaInfo (pkg/bmc/types.go) */
export interface BMCVirtualMediaStatus {
  mounted: boolean;
  image_url?: string;
  media_type?: string;
}
/** SensorReading (pkg/bmc/types.go); GET sensors returns a plain array */
export interface BMCSensor {
  name: string;
  value: number;
  units: string;
  status: string;
}
/** SystemInfo (pkg/bmc/types.go) */
export interface BMCSystemInfo {
  manufacturer: string;
  product: string;
  serial_number: string;
  firmware_version: string;
  bios_version: string;
  power_state: string;
}
/** ProvisionResult (pkg/provisioning/baremetal) */
export interface BMCProvisionStatus {
  provision_id: string;
  profile_id: string;
  /** pending, connecting, setting_boot, mounting_iso, powering_on, installing, finalizing, complete or failed */
  status: string;
  message?: string;
  started_at: string;
  updated_at: string;
}
/** CertificateInfo (pkg/webservice/v1/bmc/types.go): metadata, no PEM */
export interface BMCWebCertificate {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
  subject_alternative_names?: string[];
  fingerprint: string;
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
  mountISO: (isoURL: string) => Promise<void>;
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
 * `/api/v1/bmc/{profileID}/...` routes. Only the newest load is applied, and
 * a mutation drops every read started before it, so an older refresh that
 * finishes last never overwrites the state read after the mutation.
 */
export function useBMC(profileID: string): UseBMCResult {
  const [loaded, setLoaded] = React.useState<LoadedBMC | null>(null);
  const generation = React.useRef(0);

  const apply = React.useCallback((next: LoadedBMC) => setLoaded(next), []);

  const load = React.useCallback(async () => {
    const g = ++generation.current;
    const next = await loadBMC(profileID);
    if (g === generation.current) {
      apply(next);
    }
  }, [profileID, apply]);

  React.useEffect(() => {
    if (!profileID) {
      return;
    }
    void load();
    return () => {
      generation.current++;
    };
  }, [profileID, load]);

  const refetch = React.useCallback(async () => {
    if (profileID) {
      await load();
    }
  }, [profileID, load]);

  const mutate = React.useCallback(
    async (op: string, method: "POST" | "DELETE", body?: unknown) => {
      generation.current++;
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
    mountISO: (isoURL) => mutate("virtual-media", "POST", { iso_url: isoURL }),
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
    ["sensors", "sensors", (v) => (Array.isArray(v) ? (v as BMCSensor[]) : [])],
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
