'use client';

import { useMemo } from 'react';
import { useVPN } from 'trusted-platform-sdk';
import type { ApiResponse, VPNPeer, VPNPosturePolicy } from 'trusted-platform-sdk';

/** The enrol-peer form: zones is the comma-separated text the operator typed. */
export interface VPNPeerDraft {
  tenantId: string;
  deviceId: string;
  zones: string;
}

/** The posture-policy form. */
export interface VPNPolicyDraft {
  tenantId: string;
  name: string;
  module: string;
  isNew?: boolean;
}

export interface UseVpnOpsResult {
  /** EnrolPeer: enrol a device, or replace the zones of its enrolment. */
  enrolPeer: (draft: VPNPeerDraft) => Promise<VPNPeer | undefined>;
  /** RevokePeer: revoke a peer's enrolment. */
  revokePeer: (tenantId: string, deviceId: string) => Promise<void>;
  /** GetPosturePolicy: the stored policy, module included. */
  getPosturePolicy: (tenantId: string, name: string) => Promise<VPNPosturePolicy>;
  /** SetPosturePolicy: create or replace a policy; a module that does not compile is refused. */
  setPosturePolicy: (draft: VPNPolicyDraft) => Promise<VPNPosturePolicy | undefined>;
  /** DeletePosturePolicy: delete a policy. */
  deletePosturePolicy: (tenantId: string, name: string) => Promise<void>;
}

/** Splits the zones text on commas, trimmed, without empties or duplicates. */
export function parseZones(text: string): string[] {
  const zones = text
    .split(',')
    .map((zone) => zone.trim())
    .filter((zone) => zone !== '');
  return Array.from(new Set(zones));
}

function unwrap<T>(response: ApiResponse<T>): T | undefined {
  if (response.error !== undefined || response.success === false) {
    throw new Error(response.error?.message ?? 'Request failed');
  }
  return response.data;
}

function required(value: string, label: string): string {
  const trimmed = value.trim();
  if (trimmed === '') {
    throw new Error(`${label} is required`);
  }
  return trimmed;
}

/**
 * The VPN page's write and lookup operations over the SDK's VPNService. Each
 * one validates its input, calls the SDK, and throws the server's message on
 * failure; the caller owns toasts and refetches.
 */
export function useVpnOps(): UseVpnOpsResult {
  const vpn = useVPN();

  return useMemo<UseVpnOpsResult>(
    () => ({
      enrolPeer: async (draft) => {
        const tenantId = required(draft.tenantId, 'Tenant');
        const deviceId = required(draft.deviceId, 'Device ID');
        // Enrolling an enrolled device replaces its zones and keeps its first
        // enrolment time (docs/vpn/cli.md).
        const data = unwrap(await vpn.enrolPeer({ tenantId, deviceId, zones: parseZones(draft.zones) }));
        return data?.peer;
      },
      revokePeer: async (tenantId, deviceId) => {
        unwrap(await vpn.revokePeer(tenantId, deviceId));
      },
      getPosturePolicy: async (tenantId, name) => {
        const policy = unwrap(await vpn.getPosturePolicy(tenantId, name))?.policy;
        if (!policy) {
          throw new Error(`Posture policy ${name} not found`);
        }
        return policy;
      },
      setPosturePolicy: async (draft) => {
        const tenantId = required(draft.tenantId, 'Tenant');
        const name = required(draft.name, 'Name');
        required(draft.module, 'Module');
        const data = unwrap(await vpn.setPosturePolicy({ tenantId, name, module: draft.module }));
        return data?.policy;
      },
      deletePosturePolicy: async (tenantId, name) => {
        unwrap(await vpn.deletePosturePolicy(tenantId, name));
      },
    }),
    [vpn]
  );
}
