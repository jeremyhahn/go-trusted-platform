"use client";

/**
 * NTP hook: GetStatus, ListSources and Step (docs/ntp/api.md).
 *
 * Calls the platform's API client directly on the three NTP routes, so the
 * page works against an SDK build that predates `PlatformClient.ntp`.
 */

import { useMemo } from "react";
import {
  usePlatformClient,
  type GetNTPStatusResponse,
  type ListNTPSourcesResponse,
  type NTPSource as SdkNTPSource,
  type NTPStatus as SdkNTPStatus,
} from "trusted-platform-sdk";

export type NTPStatus = SdkNTPStatus;
export type NTPSource = SdkNTPSource;
export type NTPStatusResponse = GetNTPStatusResponse;
export type NTPSourcesResponse = ListNTPSourcesResponse;

/**
 * useNTP returns the node's NTP operations (GetStatus, ListSources, Step)
 * through the SDK's NTP service.
 */
export function useNTP() {
  const client = usePlatformClient();
  return useMemo(
    () => ({
      getStatus: () => client.ntp.getStatus(),
      listSources: () => client.ntp.listSources(),
      step: () => client.ntp.step(),
    }),
    [client],
  );
}

/** Whether the Step control is allowed, and the reason when it is not. */
export interface NTPStepCapability {
  allowed: boolean;
  reason: string | null;
}

/**
 * ntpStepCapability is the capability gate of the Step control. Step is
 * allowed only after a successful status read whose result is current: a
 * node without an `ntp:` configuration answers every NTP route with 503,
 * and a failed refresh leaves a stale status, so Step is gated off with the
 * server's reason in both cases.
 */
export function ntpStepCapability({
  status,
  error,
}: {
  status: NTPStatus | undefined;
  error: { message: string } | null;
}): NTPStepCapability {
  if (error) {
    return { allowed: false, reason: `NTP is unavailable on this node: ${error.message}` };
  }
  if (!status) {
    return { allowed: false, reason: "The NTP status has not been read yet." };
  }
  return { allowed: true, reason: null };
}
