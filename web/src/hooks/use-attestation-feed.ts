"use client";

/**
 * useAttestationFeed reaches two attestation operations through the SDK
 * client:
 *
 * - DescribeCallerPolicy: `GET /api/v1/attestation/callers`, through the
 *   SDK's `attestation.describeCallers()`.
 * - PollDeviceVerdicts: `GET /api/v1/attestation/verdicts`, through the SDK
 *   API client, because the SDK has no verdicts poll yet. The verdicts
 *   payload is protojson: fields are lowerCamelCase and uint64 values (such
 *   as `deviceId`) arrive as decimal strings.
 *
 * Both routes are admin-gated, and the verdicts route answers 403 for a
 * session that names no tenant.
 */

import { useMemo } from "react";
import { usePlatformClient, type CallerPolicyDescription } from "trusted-platform-sdk";

/** platform.v1.DeviceVerdictEvent as protojson. */
export interface DeviceVerdictEvent {
  eventId: string;
  recordedAt?: string;
  deviceId: string;
  tenantId: string;
  hostId: string;
  serial: string;
  passed: boolean;
  cryptographic: boolean;
  reason: string;
}

/** platform.v1.PollDeviceVerdictsResponse as protojson. */
export interface PollDeviceVerdictsResponse {
  cursor: string;
  verdicts: DeviceVerdictEvent[];
}

export interface PollDeviceVerdictsOptions {
  cursor?: string;
  waitMs?: number;
}

const VERDICTS_PATH = "/v1/attestation/verdicts";

/** verdictsPath builds the verdicts poll path with its cursor and wait_ms query. */
export function verdictsPath(opts: PollDeviceVerdictsOptions = {}): string {
  const params = new URLSearchParams();
  if (typeof opts.cursor === "string" && opts.cursor !== "") {
    params.set("cursor", opts.cursor);
  }
  if (typeof opts.waitMs === "number" && Number.isFinite(opts.waitMs) && opts.waitMs >= 0) {
    params.set("wait_ms", String(Math.floor(opts.waitMs)));
  }
  const query = params.toString();
  return query === "" ? VERDICTS_PATH : `${VERDICTS_PATH}?${query}`;
}

/** callerPolicySummary states in one line what the caller policy admits. */
export function callerPolicySummary(d?: CallerPolicyDescription): string {
  if (d === undefined || d.admits_nobody) {
    return "Admits no caller";
  }
  if (d.list_valid === false) {
    return "Caller list invalid";
  }
  return `${d.strategy}: ${d.identities.length} identities`;
}

export function useAttestationFeed() {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      describeCallers: () => client.attestation.describeCallers(),
      pollVerdicts: (opts?: PollDeviceVerdictsOptions) =>
        api.get<PollDeviceVerdictsResponse>(verdictsPath(opts)),
    };
  }, [client]);
}
