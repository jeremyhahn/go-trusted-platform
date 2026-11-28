"use client";

/**
 * BMC status and provisioning hook (#2039).
 *
 * Calls BMCService.PowerStatus (`GET /power`), GetSensors (`GET /sensors`),
 * GetSystemInfo (`GET /system-info`), GetWebCertificate (`GET /cert`),
 * Provision (`POST /provision`) and ProvisionStatus (`GET /provision`), served
 * under `/api/v1/bmc/{profileID}` (pkg/webservice/v1/bmc/handler.go).
 *
 * It goes through the SDK BMCService (`client.bmc`), which sends Provision
 * with retries off.
 *
 * Provision reboots the host into the installer, so a control that calls it
 * must confirm first.
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

/** PowerStatus answer: `on`, `off` or `unknown`. */
export interface BMCPowerState {
  state: string;
}

/** One GetSensors reading (pkg/bmc SensorReading); status ok, warning or critical. */
export interface BMCSensorReading {
  name: string;
  value: number;
  units: string;
  status: string;
}

/** GetSystemInfo answer (pkg/bmc SystemInfo). */
export interface BMCSystemInfo {
  manufacturer: string;
  product: string;
  serial_number: string;
  firmware_version: string;
  bios_version: string;
  power_state: string;
}

/** GetWebCertificate answer (pkg/bmc CertificateInfo). */
export interface BMCWebCertificate {
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  days_remaining: number;
}

/** Provision and ProvisionStatus answer (pkg/provisioning/baremetal ProvisionResult). */
export interface BMCProvisionResult {
  provision_id: string;
  profile_id: number;
  status: string;
  message?: string;
  started_at: string;
  updated_at: string;
}

/** Provision statuses after which the provision no longer changes. */
export const BMC_PROVISION_DONE = ["complete", "failed"] as const;

/** true when the provision status is complete or failed. */
export function isProvisionDone(status: string): boolean {
  return (BMC_PROVISION_DONE as readonly string[]).includes(status);
}

/** Sensor readings whose status is not "ok", in input order. */
export function sensorsNeedingAttention(readings: BMCSensorReading[]): BMCSensorReading[] {
  return readings.filter((r) => r.status !== "ok");
}

/** The SDK client path of one BMC operation for a profile. */
export function bmcStatusPath(profileID: string, op: string): string {
  return `/v1/bmc/${encodeURIComponent(profileID)}/${op}`;
}

export function useBMCStatus(profileID: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const bmc = client.bmc;
    return {
      getPower: () => bmc.getPowerStatus(profileID),
      getSensors: () => bmc.getSensors(profileID),
      getSystemInfo: () => bmc.getSystemInfo(profileID),
      getWebCertificate: () => bmc.getWebCertificate(profileID),
      // A provision reboots the host into the installer: the SDK sends it
      // with retries off, so a dropped reply does not start it twice.
      provision: (isoURL?: string) =>
        bmc.provision(profileID, isoURL?.trim() ? { iso_url: isoURL.trim() } : {}),
      getProvisionStatus: () => bmc.getProvisionStatus(profileID),
    };
  }, [client, profileID]);
}
