"use client";

import { useCallback } from "react";
import { useApi, useSDN } from "trusted-platform-sdk";
import type {
  ApiResponse,
  DeleteNetworkZoneResponse,
  NetworkZone,
  NetworkZoneSpec,
} from "trusted-platform-sdk";

function expectOk<T>(response: ApiResponse<T>, operation: string): ApiResponse<T> {
  if (response.error || response.success === false) {
    throw new Error(response.error?.message || `${operation} failed`);
  }
  return response;
}

/**
 * Network zones over the SDN REST routes GET/POST /v1/sdn/zones and
 * PUT/DELETE /v1/sdn/zones/{name} (#2065). Each mutation throws the
 * server's message on a refusal and lists the zones again on success.
 */
export interface UseNetworkZonesResult {
  zones: NetworkZone[];
  isLoading: boolean;
  error: Error | undefined;
  refetch: () => void;
  createZone: (zone: NetworkZoneSpec) => Promise<ApiResponse<NetworkZone>>;
  updateZone: (name: string, zone: NetworkZoneSpec) => Promise<ApiResponse<NetworkZone>>;
  deleteZone: (name: string) => Promise<ApiResponse<DeleteNetworkZoneResponse>>;
}

export function useNetworkZones(): UseNetworkZonesResult {
  const sdn = useSDN();
  const { data, isLoading, error, refetch } = useApi(() => sdn.listNetworkZones(), [sdn]);

  const createZone = useCallback(
    async (zone: NetworkZoneSpec) => {
      const res = expectOk(await sdn.createNetworkZone(zone), "Create zone");
      void refetch();
      return res;
    },
    [sdn, refetch],
  );
  const updateZone = useCallback(
    async (name: string, zone: NetworkZoneSpec) => {
      const res = expectOk(await sdn.updateNetworkZone(name, zone), "Update zone");
      void refetch();
      return res;
    },
    [sdn, refetch],
  );
  const deleteZone = useCallback(
    async (name: string) => {
      const res = expectOk(await sdn.deleteNetworkZone(name), "Delete zone");
      void refetch();
      return res;
    },
    [sdn, refetch],
  );

  return {
    zones: data?.zones ?? [],
    isLoading,
    error: error ?? undefined,
    refetch: () => {
      void refetch();
    },
    createZone,
    updateZone,
    deleteZone,
  };
}
