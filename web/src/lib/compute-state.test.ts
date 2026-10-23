import { describe, expect, it } from "vitest";

import { containerStatus, vmStateName, vmStatus } from "./compute-state";

// #482: the daemon answers compute requests in protojson, so a VM's state is
// VM_STATE_RUNNING, not RUNNING. Lowercasing the wire name made every VM's
// status "vm_state_running", which matched no filter and no badge.

describe("compute state", () => {
  it("shows a VM state without its proto prefix", () => {
    expect(vmStateName("VM_STATE_RUNNING")).toBe("RUNNING");
    expect(vmStateName("VM_STATE_MIGRATING")).toBe("MIGRATING");
  });

  it("reads VM states into console statuses", () => {
    expect(vmStatus("VM_STATE_RUNNING")).toBe("running");
    expect(vmStatus("VM_STATE_STOPPED")).toBe("stopped");
  });

  it("reads container states into console statuses", () => {
    expect(containerStatus("CONTAINER_STATE_RUNNING")).toBe("running");
    expect(containerStatus("CONTAINER_STATE_ERROR")).toBe("error");
  });

  it("does not strip the other resource's prefix", () => {
    expect(containerStatus("VM_STATE_RUNNING" as never)).toBe("vm_state_running");
  });

  it("shows a missing state as creating rather than failing", () => {
    expect(vmStateName(undefined)).toBeUndefined();
    expect(vmStatus(undefined)).toBe("creating");
    expect(containerStatus(undefined)).toBe("creating");
  });
});
