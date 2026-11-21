"use client";

import { useCallback } from "react";
import { useApi, useMutation, useDNS } from "trusted-platform-sdk";
import type { DNSSECStatus, GetDNSSECStatusResponse, SignZoneResponse } from "trusted-platform-sdk";

/**
 * DNSSEC status and zone signing for one zone (#2060).
 *
 * Reads the status through client.dns.getDNSSECStatus and signs the zone
 * through client.dns.signZone, refetching the status after a successful
 * signing. An empty zone name fetches nothing.
 */
export function useDNSSEC(zoneName: string) {
  const dns = useDNS();

  const { data, isLoading, error, refetch } = useApi<GetDNSSECStatusResponse>(
    () => dns.getDNSSECStatus(zoneName),
    [zoneName],
    { enabled: zoneName !== "" }
  );

  const { mutateAsync, isLoading: isSigning } = useMutation<SignZoneResponse, void>(() =>
    dns.signZone(zoneName)
  );

  const signZone = useCallback(async () => {
    const signed = await mutateAsync(undefined);
    await refetch();
    return signed;
  }, [mutateAsync, refetch]);

  return {
    status: data?.status as DNSSECStatus | undefined,
    isLoading,
    error,
    refetch,
    signZone,
    isSigning,
  };
}
