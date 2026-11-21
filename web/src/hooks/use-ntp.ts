"use client";

/**
 * NTP hook: GetStatus, ListSources and Step (docs/ntp/api.md).
 *
 * Calls the SDK's NTPService on `client.ntp` (#2058); the types are the
 * SDK's, under the names this hook has always exported.
 */

import { useMemo } from "react";
import {
  usePlatformClient,
  type GetNTPStatusResponse,
  type ListNTPSourcesResponse,
  type NTPSource as SDKNTPSource,
  type NTPStatus as SDKNTPStatus,
} from "trusted-platform-sdk";

/** Node clock synchronisation status (protojson, lowerCamelCase). */
export type NTPStatus = SDKNTPStatus;

/** One configured time source. */
export type NTPSource = SDKNTPSource;

export type NTPStatusResponse = GetNTPStatusResponse;

export type NTPSourcesResponse = ListNTPSourcesResponse;

export function useNTP() {
  const client = usePlatformClient();
  return useMemo(
    () => ({
      getStatus: () => client.ntp.getStatus(),
      listSources: () => client.ntp.listSources(),
      step: () => client.ntp.step(),
    }),
    [client]
  );
}
