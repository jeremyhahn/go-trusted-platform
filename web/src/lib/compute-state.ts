import type { ContainerState, VMState } from "trusted-platform-sdk";

import type { Container, VM } from "@/types/infrastructure";

const VM_STATE_PREFIX = "VM_STATE_";
const CONTAINER_STATE_PREFIX = "CONTAINER_STATE_";

function withoutPrefix(prefix: string, value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

/**
 * vmStateName is the VM state the console shows: the proto name the daemon
 * sends (`VM_STATE_RUNNING`) without its type prefix (`RUNNING`).
 */
export function vmStateName(state: VMState | undefined): string | undefined {
  return withoutPrefix(VM_STATE_PREFIX, state);
}

/**
 * vmStatus reads a VM's state into the console's VM status (`running`). A VM
 * the daemon reports no state for is shown as creating.
 */
export function vmStatus(state: VMState | undefined): VM["status"] {
  return (vmStateName(state)?.toLowerCase() || "creating") as VM["status"];
}

/**
 * containerStatus reads a container's state (`CONTAINER_STATE_RUNNING`) into
 * the console's container status (`running`). A container the daemon reports
 * no state for is shown as creating.
 */
export function containerStatus(state: ContainerState | undefined): Container["status"] {
  return (withoutPrefix(CONTAINER_STATE_PREFIX, state)?.toLowerCase() || "creating") as Container["status"];
}
