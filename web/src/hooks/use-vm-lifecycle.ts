"use client";

/**
 * VM lifecycle operations for one VM through the SDK client.
 *
 * GetVM, GetVMMetrics and AttestVM go through `client.compute`. SuspendVM and
 * ResumeVM go as `POST /api/v1/compute/vms/{id}/suspend|resume` on the SDK API
 * client, because the SDK ComputeService has no method for them on main.
 */

import { useMemo } from "react";
import { usePlatformClient, type VMState } from "trusted-platform-sdk";

/** The `{status}` answer of SuspendVM and ResumeVM. */
export interface VMOpStatus {
  status?: { success?: boolean; message?: string };
}

const VM_STATE_PREFIX = "VM_STATE_";
const RUNNING: VMState = "VM_STATE_RUNNING" as VMState;
const PAUSED: VMState = "VM_STATE_PAUSED" as VMState;

/** The API-client path of a suspend or resume call for one VM. */
export function vmOpPath(vmId: string, op: "suspend" | "resume"): string {
  return `/v1/compute/vms/${encodeURIComponent(vmId)}/${op}`;
}

/** 'VM_STATE_RUNNING' -> 'Running', 'VM_STATE_PAUSED' -> 'Paused' (strip the prefix, lower-case, capitalise the first letter); undefined or '' -> 'Unknown'. */
export function vmStateLabel(state?: string): string {
  if (!state) {
    return "Unknown";
  }
  const word = (state.startsWith(VM_STATE_PREFIX) ? state.slice(VM_STATE_PREFIX.length) : state).toLowerCase();
  if (!word) {
    return "Unknown";
  }
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** Only a running VM can be suspended. */
export function canSuspend(state?: string): boolean {
  return state === RUNNING;
}

/** Only a paused VM can be resumed. */
export function canResume(state?: string): boolean {
  return state === PAUSED;
}

/** 32 random bytes from crypto.getRandomValues, base64 (btoa over the bytes). */
export function vmAttestNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) {
    bin += String.fromCharCode(b);
  }
  return btoa(bin);
}

/** A uint64 that protojson sent as a string or a number, as a number; undefined -> 0. */
export function wireNumber(v: number | string | undefined): number {
  if (v === undefined) {
    return 0;
  }
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? n : 0;
}

/** The lifecycle operations of one VM, bound to the platform client. */
export function useVMLifecycle(vmId: string) {
  const client = usePlatformClient();
  return useMemo(() => {
    const api = client.getApiClient();
    return {
      getVM: () => client.compute.getVM(vmId),
      getMetrics: () => client.compute.getVMMetrics(vmId),
      suspend: () => api.post<VMOpStatus>(vmOpPath(vmId, "suspend"), {}),
      resume: () => api.post<VMOpStatus>(vmOpPath(vmId, "resume"), {}),
      attest: (nonce: string = vmAttestNonce()) => client.compute.attestVM({ vmId, nonce }),
    };
  }, [client, vmId]);
}
