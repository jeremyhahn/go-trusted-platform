/**
 * The device-facing profile: what a node reads about itself over mTLS.
 *
 * `GET /api/v1/device/profile` (`pkg/webservice/v1/device/handler.go`,
 * `ProfileResponse`) is a different wire from the operator profile in
 * `./device.ts`. It is camelCase by contract (`docs/device/api.md` §3.2): the
 * primary field is `trustedNetwork`, an optional `provisioningNetwork` sibling
 * carries the enrollment-phase network, and there is no `production_network`,
 * `provisioning_network` or `quarantine_network` in any spelling. Two wires,
 * two types — nothing here is shared with `DeviceProfile` (#402, #378).
 */

/** One network as the device receives it: VLAN plus either DHCP or a static address. */
export interface DeviceSelfServiceNetwork {
  /** VLAN the device's port is placed on */
  vlan: number;
  /** Whether the device should DHCP on this network */
  useDHCP: boolean;
  /** Static IP, when `useDHCP` is false */
  staticIP?: string;
  /** Default gateway */
  gateway?: string;
  /** DNS servers */
  dns?: string[];
}

/** One access-control rule applied to the device's port. */
export interface DeviceSelfServiceACL {
  /** Rule name */
  name: string;
  /** Evaluation priority; higher wins */
  priority: number;
  /** Match criteria, key/value */
  match: Record<string, string>;
  /** `allow` or `deny` */
  action: string;
}

/** Ingress/egress rate limits applied to the device's port, in Mbps. */
export interface DeviceSelfServiceRateLimit {
  /** Inbound limit */
  ingressMbps: number;
  /** Outbound limit */
  egressMbps: number;
}

/** Body of `GET /api/v1/device/profile`. */
export interface DeviceSelfServiceProfile {
  /** The device's serial, as resolved from its client certificate */
  serialNumber: string;
  /** The network the device lives on once activated */
  trustedNetwork: DeviceSelfServiceNetwork;
  /**
   * The enrollment-phase network, when the profile defines one. The server
   * uses its VLAN as the fail-closed revert target for the physical switch
   * move during activation.
   */
  provisioningNetwork?: DeviceSelfServiceNetwork;
  /** Port ACLs */
  acls?: DeviceSelfServiceACL[];
  /** Port rate limits */
  rateLimit?: DeviceSelfServiceRateLimit;
}
