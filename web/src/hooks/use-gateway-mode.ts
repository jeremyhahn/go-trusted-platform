"use client";

/**
 * Gateway mode hook: SetGatewayMode, GetGatewaySnapshot and
 * ListGatewaySnapshots (#2051).
 *
 * Routes: `POST /api/v1/gateway/mode` (body `{modes}`, a bitmask of the
 * proto GatewayMode values), `GET /api/v1/gateway/state` and
 * `GET /api/v1/gateway/state/{id}`. Every call goes through the SDK
 * GatewayService from `useGateway()`, not a hand-written fetch.
 *
 * Changing the mode reconfigures the gateway's data plane, so a control
 * that calls `setModes` must ask the operator to confirm first.
 */

import { useMemo } from "react";
import { useGateway } from "trusted-platform-sdk";

/** The proto GatewayMode bits (pkg/api/grpc/proto/gateway.proto). */
export const GATEWAY_MODE_BITS = { OVERLAY: 1, EDGE: 2, TRANSIT: 4 } as const;

export type GatewayModeName = keyof typeof GATEWAY_MODE_BITS;

const MODE_ORDER: GatewayModeName[] = ["OVERLAY", "EDGE", "TRANSIT"];

/** OR of the named bits; duplicates count once. */
export function modesToMask(modes: GatewayModeName[]): number {
  return modes.reduce((mask, mode) => mask | GATEWAY_MODE_BITS[mode], 0);
}

/** Names whose bit is set, in OVERLAY, EDGE, TRANSIT order. */
export function maskToModes(mask: number): GatewayModeName[] {
  return MODE_ORDER.filter((mode) => (mask & GATEWAY_MODE_BITS[mode]) !== 0);
}

export function useGatewayMode() {
  const gateway = useGateway();
  return useMemo(
    () => ({
      setModes: (modes: GatewayModeName[]) => gateway.setMode({ modes: modesToMask(modes) }),
      listSnapshots: () => gateway.listState(),
      getSnapshot: (gatewayId: string) => gateway.getState(gatewayId),
    }),
    [gateway],
  );
}
