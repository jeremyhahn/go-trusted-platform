/**
 * The device-facing profile is its own wire, and these say why the SDK models
 * it separately from DeviceProfile.
 *
 * `GET /api/v1/device/profile` answers in camelCase — `trustedNetwork`,
 * `provisioningNetwork`, `staticIP`, `useDHCP` — while the operator profile
 * answers in snake_case with a `networks` map. Until #402 the SDK had no type
 * for this surface at all; the console had borrowed `provisioningNetwork` from
 * it onto the operator type, which is how #378's hybrid came to be. The
 * fixture below is the api.md §3.2 example verbatim, so a drift in the doc, the
 * type or the server's tags fails here or in the Go parity test.
 */

import { describe, it, expect } from 'vitest';
import type { DeviceSelfServiceProfile } from '../device-self-service.js';

/** docs/device/api.md §3.2, with the optional provisioning sibling filled in. */
const WIRE = `{
  "serialNumber": "SRV-2024-001",
  "trustedNetwork": { "vlan": 200, "useDHCP": false,
                      "staticIP": "203.0.113.50", "gateway": "203.0.113.1",
                      "dns": ["203.0.113.1"] },
  "provisioningNetwork": { "vlan": 998, "useDHCP": true },
  "acls":      [{ "name": "allow-cp", "priority": 100, "match": {"dstPort": "443"}, "action": "allow" }],
  "rateLimit": { "ingressMbps": 100, "egressMbps": 100 }
}`;

describe('device self-service profile', () => {
  it('decodes the documented body with every field populated', () => {
    const profile = JSON.parse(WIRE) as DeviceSelfServiceProfile;

    expect(profile.serialNumber).toBe('SRV-2024-001');
    expect(profile.trustedNetwork.vlan).toBe(200);
    expect(profile.trustedNetwork.useDHCP).toBe(false);
    expect(profile.trustedNetwork.staticIP).toBe('203.0.113.50');
    expect(profile.trustedNetwork.gateway).toBe('203.0.113.1');
    expect(profile.trustedNetwork.dns).toEqual(['203.0.113.1']);
    expect(profile.provisioningNetwork?.vlan).toBe(998);
    expect(profile.provisioningNetwork?.useDHCP).toBe(true);
    expect(profile.acls?.[0]?.match).toEqual({ dstPort: '443' });
    expect(profile.rateLimit?.egressMbps).toBe(100);
  });

  it('is a different wire from the operator profile, in both directions', () => {
    // Compile-time: the operator profile's map and selectors do not exist here,
    // and the device-facing names are camelCase, not the snake_case a habit
    // would reach for. Each line fails to typecheck if the declaration drifts.
    type Operator = Extract<
      keyof DeviceSelfServiceProfile,
      'networks' | 'enrollment_network' | 'post_enrollment_network' | 'failure_network'
    >;
    const noOperatorFields: [Operator] extends [never] ? true : false = true;
    expect(noOperatorFields).toBe(true);

    type Snake = Extract<
      keyof DeviceSelfServiceProfile['trustedNetwork'],
      'static_ip' | 'use_dhcp' | 'production_network'
    >;
    const noSnakeCase: [Snake] extends [never] ? true : false = true;
    expect(noSnakeCase).toBe(true);

    // Runtime control: the server's field is `staticIP`, so a client reading
    // the operator spelling gets undefined — the defect class this type exists
    // to make visible.
    const profile = JSON.parse(WIRE) as DeviceSelfServiceProfile;
    const asOperatorSpelling = profile.trustedNetwork as unknown as { static_ip?: string };
    expect(asOperatorSpelling.static_ip).toBeUndefined();
    expect(profile.trustedNetwork.staticIP).toBe('203.0.113.50');
  });

  it('treats the provisioning sibling as optional — a DHCP-only trusted body is complete', () => {
    const minimal = JSON.parse(
      `{"serialNumber":"SRV-2","trustedNetwork":{"vlan":200,"useDHCP":true}}`
    ) as DeviceSelfServiceProfile;

    expect(minimal.provisioningNetwork).toBeUndefined();
    expect(minimal.acls).toBeUndefined();
    expect(minimal.rateLimit).toBeUndefined();
    expect(minimal.trustedNetwork.staticIP).toBeUndefined();
  });
});
