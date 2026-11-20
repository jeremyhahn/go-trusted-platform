"use client";

import * as React from "react";
import { usePlatformClient, type ApiResponse } from "trusted-platform-sdk";

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
  /** PowerOn, PowerOff, PowerReset, PowerCycle: POST /bmc/{id}/power {action} */
  powerAction: (action: BMCPowerAction) => Promise<void>;
}

/** The chassis power actions the server's POST /bmc/{id}/power accepts */
export type BMCPowerAction = "on" | "off" | "reset" | "cycle";

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

/** The SDK's BMCService, as the platform client carries it */
type BMCClient = ReturnType<typeof usePlatformClient>["bmc"];

/** Unwraps an SDK ApiResponse, or throws the server's error message */
async function unwrap<T>(pending: ApiResponse<T> | Promise<ApiResponse<T>>): Promise<T> {
  const res = await pending;
  if (!res.success) {
    throw new Error(res.error?.message || "BMC request failed");
  }
  return res.data as T;
}

/**
 * useBMC reads and drives one BMC profile through the SDK's BMCService
 * (`usePlatformClient().bmc`, the `/api/v1/bmc/{profileID}/...` routes). Only the newest load is applied, and
 * a mutation drops every read started before it, so an older refresh that
 * finishes last never overwrites the state read after the mutation.
 */
export function useBMC(profileID: string): UseBMCResult {
  const [loaded, setLoaded] = React.useState<LoadedBMC | null>(null);
  const generation = React.useRef(0);
  // The client object may differ per render; the callbacks read the
  // newest one so their identities, and the load effect, stay stable.
  const client = usePlatformClient().bmc;
  const service = React.useRef<BMCClient>(client);
  // The profile the hook shows now: a mutation started for an earlier
  // profile must not refresh that profile over this one.
  const currentProfile = React.useRef(profileID);
  // Synced after each commit, before the load effect below runs.
  React.useEffect(() => {
    service.current = client;
    currentProfile.current = profileID;
  });

  const apply = React.useCallback((next: LoadedBMC) => setLoaded(next), []);

  const load = React.useCallback(async () => {
    const g = ++generation.current;
    const next = await loadBMC(service.current, profileID);
    if (g === generation.current) {
      apply(next);
    }
  }, [profileID, apply]);

  React.useEffect(() => {
    if (!profileID) {
      return;
    }
    const gen = generation;
    void load();
    return () => {
      gen.current++;
    };
  }, [profileID, load]);

  const refetch = React.useCallback(async () => {
    if (profileID) {
      await load();
    }
  }, [profileID, load]);


  const mutate = React.useCallback(
    async (send: (bmc: BMCClient, id: string) => Promise<ApiResponse<unknown>>) => {
      generation.current++;
      try {
        await unwrap(send(service.current, profileID));
      } finally {
        // The bump above discarded any read in flight, the initial load
        // included: reload even when the mutation failed, or isLoading
        // never clears. The mutation's error still reaches the caller.
        if (currentProfile.current === profileID) {
          await refetch();
        }
      }
    },
    [profileID, refetch]
  );

  const current = loaded && loaded.profileID === profileID ? loaded : null;

  return {
    ...(current?.state ?? EMPTY),
    isLoading: current === null,
    errors: current?.errors ?? {},
    refetch,
    setBootDevice: (request) => mutate((bmc, id) => bmc.setBootDevice(id, request)),
    mountISO: (isoURL) => mutate((bmc, id) => bmc.mountISO(id, { iso_url: isoURL })),
    unmountISO: () => mutate((bmc, id) => bmc.unmountISO(id)),
    provision: () => mutate((bmc, id) => bmc.provision(id)),
    powerAction: (action) => mutate((bmc, id) => bmc.powerAction(id, action)),
  };
}

interface LoadedBMC {
  profileID: string;
  state: BMCState;
  errors: Partial<Record<BMCPart, string>>;
}

/** loadBMC reads every part of one profile; a failed part is an error, not a throw */
async function loadBMC(bmc: BMCClient, profileID: string): Promise<LoadedBMC> {
  const parts: Array<[BMCPart, () => Promise<ApiResponse<unknown>>, (v: unknown) => unknown]> = [
    ["power", () => bmc.getPowerStatus(profileID), (v) => v],
    ["bootDevice", () => bmc.getBootDevice(profileID), (v) => v],
    ["virtualMedia", () => bmc.getVirtualMediaStatus(profileID), (v) => v],
    ["sensors", () => bmc.getSensors(profileID), (v) => (Array.isArray(v) ? (v as BMCSensor[]) : [])],
    ["systemInfo", () => bmc.getSystemInfo(profileID), (v) => v],
    ["provisionStatus", () => bmc.getProvisionStatus(profileID), (v) => v],
    ["certificate", () => bmc.getWebCertificate(profileID), (v) => v],
  ];
  // Each read starts inside its own promise, so one that throws before it
  // answers is that part's error, not a failed load.
  const results = await Promise.allSettled(
    parts.map(([, read, pick]) => Promise.resolve().then(read).then(unwrap).then(pick))
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
