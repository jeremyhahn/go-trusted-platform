import type { DeviceStatus } from '@/types/device';

/**
 * Lifecycle states that represent an enforcement action. They always
 * win over heartbeat freshness: a quarantined/suspended/revoked node is
 * alive AND cut off, and hiding that from operators defeats the point.
 */
const ENFORCEMENT_STATES = ['quarantined', 'suspended', 'revoked'];

/** Heartbeats older than this render as Offline. */
export const HEARTBEAT_FRESHNESS_MS = 5 * 60_000;

/**
 * deriveDeviceStatus is the single source of truth for the device
 * status badge: enforcement states → disabled; no heartbeat → unknown;
 * fresh heartbeat → online; stale → offline. The list page, detail
 * page, and table all derive from here so filtering and rendering agree.
 */
export function deriveDeviceStatus(
  lifecycleState: string,
  lastHeartbeatAt?: string
): DeviceStatus {
  if (ENFORCEMENT_STATES.includes(lifecycleState)) {
    return 'disabled';
  }
  if (!lastHeartbeatAt) return 'unknown';
  const ageMs = Date.now() - new Date(lastHeartbeatAt).getTime();
  if (!Number.isFinite(ageMs)) return 'unknown';
  return ageMs < HEARTBEAT_FRESHNESS_MS ? 'online' : 'offline';
}
