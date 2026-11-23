"use client";

/**
 * BMC power actions: PowerOn, PowerOff, PowerReset and PowerCycle.
 *
 * All four share one route, `POST /api/v1/bmc/{profileID}/power` with the
 * body `{ action }` (pkg/webservice/v1/bmc/handler.go PowerAction). The hook
 * goes through the SDK BMCService (`client.bmc.powerAction`), which never
 * retries a power action.
 *
 * off, reset and cycle stop the host, so a control that calls them must ask
 * for confirmation first (see bmcPowerActionStopsHost).
 */

import { useMemo } from "react";
import { usePlatformClient } from "trusted-platform-sdk";

export const BMC_POWER_ACTIONS = ["on", "off", "reset", "cycle"] as const;

export type BMCPowerAction = (typeof BMC_POWER_ACTIONS)[number];

/** The payload of a successful power action. */
export interface BMCPowerActionResult {
  status: string;
  action: string;
}

const LABELS: Record<BMCPowerAction, string> = {
  on: "Power on",
  off: "Power off",
  reset: "Reset",
  cycle: "Power cycle",
};

/** Reports whether s is one of BMC_POWER_ACTIONS. */
export function isBMCPowerAction(s: string): s is BMCPowerAction {
  return (BMC_POWER_ACTIONS as readonly string[]).includes(s);
}

/** The API client path of a profile's power route. */
export function bmcPowerPath(profileID: string): string {
  return `/v1/bmc/${encodeURIComponent(profileID)}/power`;
}

/** "Power on", "Power off", "Reset", "Power cycle". */
export function bmcPowerActionLabel(a: BMCPowerAction): string {
  return LABELS[a];
}

/** true for off, reset and cycle: the host stops. */
export function bmcPowerActionStopsHost(a: BMCPowerAction): boolean {
  return a !== "on";
}

export function useBMCPower(profileID: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    // A power action is not idempotent: the SDK sends it with retries off,
    // so a dropped reply does not power-cycle the host twice.
    const run = (action: BMCPowerAction) => client.bmc.powerAction(profileID, action);
    return {
      run,
      powerOn: () => run("on"),
      powerOff: () => run("off"),
      reset: () => run("reset"),
      cycle: () => run("cycle"),
    };
  }, [client, profileID]);
}
