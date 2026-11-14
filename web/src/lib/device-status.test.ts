import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { HEARTBEAT_FRESHNESS_MS, deriveDeviceStatus } from "./device-status";

// #1795: the device status badge, list filter and table all derive from
// deriveDeviceStatus. These pin its precedence: enforcement wins, then a
// missing or unreadable heartbeat is unknown, then freshness decides.

const NOW = new Date("2026-11-12T12:00:00.000Z");

function ago(ms: number): string {
  return new Date(NOW.getTime() - ms).toISOString();
}

describe("deriveDeviceStatus", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("treats a heartbeat older than five minutes as stale", () => {
    expect(HEARTBEAT_FRESHNESS_MS).toBe(300_000);
  });

  it("shows every enforcement state as disabled, even with a fresh heartbeat", () => {
    for (const state of ["quarantined", "suspended", "revoked"]) {
      expect(deriveDeviceStatus(state, ago(1_000))).toBe("disabled");
      expect(deriveDeviceStatus(state)).toBe("disabled");
      expect(deriveDeviceStatus(state, "not a date")).toBe("disabled");
    }
  });

  it("matches enforcement states exactly", () => {
    expect(deriveDeviceStatus("Revoked", ago(1_000))).toBe("online");
    expect(deriveDeviceStatus(" suspended", ago(1_000))).toBe("online");
  });

  it("shows a device with no heartbeat as unknown", () => {
    expect(deriveDeviceStatus("active")).toBe("unknown");
    expect(deriveDeviceStatus("active", undefined)).toBe("unknown");
    expect(deriveDeviceStatus("active", "")).toBe("unknown");
  });

  it("shows an unreadable heartbeat as unknown", () => {
    expect(deriveDeviceStatus("active", "not a date")).toBe("unknown");
  });

  it("shows a fresh heartbeat as online", () => {
    expect(deriveDeviceStatus("active", ago(0))).toBe("online");
    expect(deriveDeviceStatus("active", ago(HEARTBEAT_FRESHNESS_MS - 1))).toBe("online");
  });

  it("shows a heartbeat from the future as online", () => {
    expect(deriveDeviceStatus("active", ago(-60_000))).toBe("online");
  });

  it("shows a heartbeat at or past the window as offline", () => {
    expect(deriveDeviceStatus("active", ago(HEARTBEAT_FRESHNESS_MS))).toBe("offline");
    expect(deriveDeviceStatus("active", ago(24 * 60 * 60_000))).toBe("offline");
  });

  it("derives from the heartbeat for any non-enforcement state", () => {
    expect(deriveDeviceStatus("", ago(1_000))).toBe("online");
    expect(deriveDeviceStatus("pending", ago(HEARTBEAT_FRESHNESS_MS + 1))).toBe("offline");
  });
});
