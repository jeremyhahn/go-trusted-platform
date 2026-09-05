/**
 * A device profile's networks are an open-keyed map plus three selector
 * strings, and these say why the client models exactly that.
 *
 * The server (`pkg/webservice/v1/device/types.go`, `ProfileFullResponse`)
 * sends `networks` keyed by logical phase name and `enrollment_network`,
 * `post_enrollment_network`, `failure_network` naming which key is active at
 * each lifecycle point. The client used to flatten that into three fixed
 * object fields — `provisioningNetwork`, `productionNetwork`,
 * `quarantineNetwork` — that the operator surface never sends, so every
 * profile rendered as "no networks" and every write under those names was
 * silently discarded (#378).
 *
 * The runtime checks here are the issue's own verification list: a phase key
 * outside the three defaults round-trips without loss, and a changed selector
 * is visible client-side. The compile-time check pins the removal.
 */

import { describe, it, expect } from 'vitest';
import {
  DEFAULT_ENROLLMENT_NETWORK,
  DEFAULT_FAILURE_NETWORK,
  DEFAULT_POST_ENROLLMENT_NETWORK,
  networkPhaseSelectors,
} from '../device.js';
import type { DeviceProfile } from '../device.js';

/** The operator profile exactly as the list route emits it, with a key the old client could not express. */
const WIRE_PROFILE = `{
  "id": "7",
  "name": "lab-worker",
  "role": "WORKER",
  "networks": {
    "provisioning": { "vlan": 998, "dhcp": true },
    "lab-dmz": { "vlan": 42, "static_ip": "10.42.0.7", "gateway": "10.42.0.1" },
    "quarantine": { "vlan": 666, "dhcp": true }
  },
  "post_enrollment_network": "lab-dmz",
  "assigned": false
}`;

describe('device profile networks', () => {
  it('round-trips a phase key outside the three defaults without loss', () => {
    const parsed = JSON.parse(WIRE_PROFILE) as DeviceProfile;
    const round = JSON.parse(JSON.stringify(parsed)) as DeviceProfile;

    expect(Object.keys(round.networks ?? {}).sort()).toEqual([
      'lab-dmz',
      'provisioning',
      'quarantine',
    ]);
    expect(round.networks?.['lab-dmz']?.vlan).toBe(42);
    expect(round.post_enrollment_network).toBe('lab-dmz');
  });

  it('exposes the active phase through the selector, not through a fixed field name', () => {
    const parsed = JSON.parse(WIRE_PROFILE) as DeviceProfile;
    const selectors = networkPhaseSelectors(parsed);

    expect(selectors.postEnrollment).toBe('lab-dmz');
    expect(parsed.networks?.[selectors.postEnrollment]?.vlan).toBe(42);

    // The control: the same profile with the selector moved lands the device
    // elsewhere, and the client sees the move. The old three-field shape had
    // no way to represent this at all.
    const moved: DeviceProfile = { ...parsed, post_enrollment_network: 'quarantine' };
    expect(networkPhaseSelectors(moved).postEnrollment).toBe('quarantine');
    expect(parsed.networks?.[networkPhaseSelectors(moved).postEnrollment]?.vlan).toBe(666);
  });

  it('has no field that holds an object where the server sends a phase-name string', () => {
    // Compile-time assertion: each of the removed names fails to typecheck if
    // it is ever reintroduced on DeviceProfile. The runtime check is incidental.
    type Removed = Extract<
      keyof DeviceProfile,
      'provisioningNetwork' | 'productionNetwork' | 'quarantineNetwork'
    >;
    const removed: [Removed] extends [never] ? true : false = true;
    expect(removed).toBe(true);

    const selectorNames: Array<keyof DeviceProfile> = [
      'enrollment_network',
      'post_enrollment_network',
      'failure_network',
    ];
    const parsed = JSON.parse(WIRE_PROFILE) as DeviceProfile;
    for (const name of selectorNames) {
      const value = parsed[name];
      expect(value === undefined || typeof value === 'string').toBe(true);
    }
  });
});

describe('networkPhaseSelectors', () => {
  it('returns the explicit selectors when the profile sets them', () => {
    const selectors = networkPhaseSelectors({
      enrollment_network: 'staging',
      post_enrollment_network: 'lab-dmz',
      failure_network: 'sinkhole',
    });

    expect(selectors).toEqual({
      enrollment: 'staging',
      postEnrollment: 'lab-dmz',
      failure: 'sinkhole',
    });
  });

  it('falls back to the server defaults for selectors the wire omitted or sent empty', () => {
    // `omitempty` drops an unset selector entirely; an explicit empty string is
    // what a client that mirrors the Go zero value sends. Both mean "default".
    const omitted = networkPhaseSelectors({});
    const empty = networkPhaseSelectors({
      enrollment_network: '',
      post_enrollment_network: '',
      failure_network: '',
    });

    for (const selectors of [omitted, empty]) {
      expect(selectors.enrollment).toBe(DEFAULT_ENROLLMENT_NETWORK);
      expect(selectors.postEnrollment).toBe(DEFAULT_POST_ENROLLMENT_NETWORK);
      expect(selectors.failure).toBe(DEFAULT_FAILURE_NETWORK);
    }
    expect([
      DEFAULT_ENROLLMENT_NETWORK,
      DEFAULT_POST_ENROLLMENT_NETWORK,
      DEFAULT_FAILURE_NETWORK,
    ]).toEqual(['provisioning', 'trusted', 'quarantine']);
  });
});
