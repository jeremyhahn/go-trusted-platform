"use client";

/**
 * SDN port state hook: GetPort and SetPortState on
 * `GET|PUT /api/v1/sdn/bridges/{name}/ports/{port}/state`
 * (pkg/webservice/v1/rest/sdn/handlers.go lines 184-205).
 *
 * Calls the SDK API client directly: the SDK `SDNService.getPort` path has no
 * server route, and the SDK has no SetPortState.
 *
 * Setting a port down cuts its traffic, so a control that does it must ask
 * the operator to confirm first.
 */

import { useMemo } from "react";
import { usePlatformClient, type Port } from "trusted-platform-sdk";

export type PortAdminState = "up" | "down";

export interface PortStateInput {
  adminState: PortAdminState;
  ingressRate?: number;
  ingressBurst?: number;
  egressRate?: number;
  egressBurst?: number;
}

export interface GetPortStateResult {
  port: Port;
}

export interface SetPortStateResult {
  status: { success: boolean; message: string };
  port?: Port;
}

export function portStatePath(bridgeId: string, portId: string): string {
  return `/v1/sdn/bridges/${encodeURIComponent(bridgeId)}/ports/${encodeURIComponent(portId)}/state`;
}

const RATE_FIELDS = ["ingressRate", "ingressBurst", "egressRate", "egressBurst"] as const;

/** The request body: adminState, plus each rate or burst only when it is a finite number > 0 (rounded down). */
export function portStateBody(input: PortStateInput): Record<string, unknown> {
  const body: Record<string, unknown> = { adminState: input.adminState };
  for (const field of RATE_FIELDS) {
    const value = input[field];
    if (typeof value === "number" && Number.isFinite(value) && value > 0) {
      const whole = Math.floor(value);
      if (whole > 0) body[field] = whole;
    }
  }
  return body;
}

export function useSDNPortState(bridgeId: string, portId: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    const path = portStatePath(bridgeId, portId);
    return {
      getPort: () => api.get<GetPortStateResult>(path),
      setPortState: (input: PortStateInput) => api.put<SetPortStateResult>(path, portStateBody(input)),
    };
  }, [client, bridgeId, portId]);
}
