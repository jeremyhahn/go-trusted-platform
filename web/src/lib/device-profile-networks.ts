/**
 * Device profile network phases as the operator surface models them.
 *
 * A profile carries an open-keyed `networks` map plus three selector strings
 * naming which entry is active for enrollment, post-enrollment and failure
 * (`pkg/webservice/v1/device/types.go`, `ProfileFullResponse`). The console
 * used to flatten that into three fixed fields the server never sends, so the
 * profiles table showed "No networks" for every profile and the static IP an
 * operator typed on create was posted under a key the server discards (#378).
 * Everything here reads and writes the map and the selectors instead.
 */

import { DEFAULT_POST_ENROLLMENT_NETWORK, networkPhaseSelectors } from 'trusted-platform-sdk';
import type { DeviceProfile, NetworkPhaseConfig, NetworkPhaseSelectors } from 'trusted-platform-sdk';

/** Lifecycle points at which a network phase is the one in use. */
export type NetworkPhaseRole = 'enrollment' | 'post-enrollment' | 'failure';

/** One entry of a profile's `networks` map with the roles its key is selected for. */
export interface NetworkPhaseRow {
  /** The map key — the logical phase name */
  name: string;
  /** The phase configuration under that key */
  config: NetworkPhaseConfig;
  /** Roles whose effective selector names this key; empty when the entry is defined but not in use */
  roles: NetworkPhaseRole[];
}

/**
 * List a profile's network phases in stable order, each marked with the
 * lifecycle roles its key is selected for.
 */
export function networkPhaseRows(profile: DeviceProfile): NetworkPhaseRow[] {
  const selectors = networkPhaseSelectors(profile);
  return Object.entries(profile.networks ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, config]) => ({ name, config, roles: rolesFor(name, selectors) }));
}

function rolesFor(name: string, selectors: NetworkPhaseSelectors): NetworkPhaseRole[] {
  const roles: NetworkPhaseRole[] = [];
  if (selectors.enrollment === name) {
    roles.push('enrollment');
  }
  if (selectors.postEnrollment === name) {
    roles.push('post-enrollment');
  }
  if (selectors.failure === name) {
    roles.push('failure');
  }
  return roles;
}

/** What the two create-from-template pages collect for a specific device. */
export interface ProfileOverrideInput {
  /** Static IP for the network the device lives on after enrollment; blank for DHCP */
  staticIp: string;
  /** TPM EK certificate serial to bind the profile to; blank when unknown */
  ekSerial: string;
  /** MAC address to bind the profile to; blank when unknown */
  macAddress: string;
}

/**
 * Build the `overrides` body for create-from-template.
 *
 * Everything device-specific travels inside `overrides`, because that is the
 * only body the server decodes on that route. A static IP belongs to the phase
 * the device lives on after enrollment, so it is written under the
 * post-enrollment key and the selector is set explicitly to make the resulting
 * profile self-describing. Returns `undefined` when every input is blank so
 * callers can pass the result straight through.
 */
export function profileOverrides(input: ProfileOverrideInput): Partial<DeviceProfile> | undefined {
  const overrides: Partial<DeviceProfile> = {};
  const ip = input.staticIp.trim();
  if (ip) {
    overrides.networks = { [DEFAULT_POST_ENROLLMENT_NETWORK]: { static_ip: ip } };
    overrides.post_enrollment_network = DEFAULT_POST_ENROLLMENT_NETWORK;
  }
  const ekSerial = input.ekSerial.trim();
  if (ekSerial) {
    overrides.ek_serial = ekSerial;
  }
  const macAddress = input.macAddress.trim();
  if (macAddress) {
    overrides.mac_address = macAddress;
  }
  return Object.keys(overrides).length > 0 ? overrides : undefined;
}
