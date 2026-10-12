/**
 * DeviceRole is the ten strings the REST API puts on the wire, and these pin
 * them.
 *
 * The type once declared the gRPC enum spellings (`SERVER`, `LOAD_BALANCER`,
 * `UNSPECIFIED`), which the REST API never sends: the server writes
 * `string(entities.DeviceRole)` (`pkg/device/entities/profile.go`), so a
 * profile created with role `server` came back as `server`, matched no member
 * of the union, and every exhaustive `Record<DeviceRole, string>` lookup fell
 * through to undefined. The type also lacked `control-plane` and `worker`, the
 * roles the bootstrap templates use. Refs #119.
 *
 * `npm run typecheck` includes this file, so the compile-time assertions here
 * fail the SDK gate if the union drifts.
 */

import { describe, it, expect } from 'vitest';
import type { DeviceProfile, DeviceRole, DeviceTemplate } from '../device.js';

/**
 * One entry per role, keyed by its wire string. `satisfies` makes this fail
 * to typecheck if the union gains a role not listed here, or loses one that is.
 */
const roleNames = {
  unknown: 'Unknown',
  'control-plane': 'Control Plane',
  gateway: 'Gateway',
  worker: 'Worker',
  server: 'Server',
  client: 'Client',
  workstation: 'Workstation',
  edge: 'Edge',
  iot: 'IoT',
  'load-balancer': 'Load Balancer',
} satisfies Record<DeviceRole, string>;

/** The values `entities.deviceRoles` maps to, in the Go declaration order. */
const SERVER_ROLES = [
  'unknown',
  'control-plane',
  'gateway',
  'worker',
  'server',
  'client',
  'workstation',
  'edge',
  'iot',
  'load-balancer',
];

describe('DeviceRole wire values', () => {
  it('is exactly the ten roles the server writes', () => {
    expect(Object.keys(roleNames)).toEqual(SERVER_ROLES);
  });

  it('carries a role from a REST body through unchanged', () => {
    const body = '{"id":"7","name":"lb-01","role":"load-balancer"}';
    const profile = JSON.parse(body) as DeviceProfile;

    expect(profile.role).toBe('load-balancer');
    expect(roleNames[profile.role]).toBe('Load Balancer');
  });

  it('names the role of a template saved without one', () => {
    // The server stores an empty role as `unknown` and reports it that way.
    const template = JSON.parse('{"id":"3","name":"bare","role":"unknown"}') as DeviceTemplate;

    expect(roleNames[template.role]).toBe('Unknown');
  });

  it('rejects the retired gRPC enum spellings at compile time', () => {
    // @ts-expect-error -- the REST API never sends the enum spelling.
    const upper: DeviceRole = 'SERVER';
    // @ts-expect-error -- the wire form is `load-balancer`.
    const underscored: DeviceRole = 'LOAD_BALANCER';
    // @ts-expect-error -- an unset role is reported as `unknown`.
    const unspecified: DeviceRole = 'UNSPECIFIED';

    for (const role of [upper, underscored, unspecified]) {
      expect(SERVER_ROLES).not.toContain(role);
    }
  });
});
