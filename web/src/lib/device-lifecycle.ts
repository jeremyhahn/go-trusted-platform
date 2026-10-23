import type { DeviceLifecycleResponse } from 'trusted-platform-sdk';

/**
 * The operator lifecycle transitions the console offers (#250). Each one is
 * a dedicated control-plane flow — `POST /v1/devices/{id}/disable` and
 * `POST /v1/devices/{id}/enable` — never the generic PUT, whose update
 * restores every server-owned field from the stored record.
 */
export type DeviceToggle = 'enable' | 'disable';

/** The tooltip on a revoked device, which offers no toggle. */
export const DEVICE_REVOKED_NO_TOGGLE =
  'A revoked device cannot be enabled or disabled: revocation is terminal.';

/**
 * deviceToggle names the transition to offer for a device in
 * lifecycleState: a suspended device can be enabled, a revoked one has no
 * transition, and every other state is offered Disable. The control plane
 * still decides — a refusal (no SDN engine, no switch port on record)
 * comes back as an error the caller shows.
 */
export function deviceToggle(lifecycleState: string | undefined): DeviceToggle | null {
  if (lifecycleState === 'suspended') return 'enable';
  if (lifecycleState === 'revoked') return null;
  return 'disable';
}

/**
 * deviceDisableConfirmation is the question asked before a disable: it
 * cuts a live machine off the fabric, so the operator confirms it the way
 * they confirm a delete.
 */
export function deviceDisableConfirmation(name: string): string {
  return `Disable ${name}? Its switch port is blocked until an operator enables it again.`;
}

/**
 * deviceToggleSuccess is the toast text for a transition the control plane
 * applied. An enabled device is only re-admitted to quarantine; saying it
 * was "enabled" without that would tell the operator it is back in
 * service when it still has to re-attest.
 */
export function deviceToggleSuccess(toggle: DeviceToggle, result: DeviceLifecycleResponse): string {
  if (toggle === 'disable') {
    return 'Device disabled: its switch port is blocked.';
  }
  if (result.reattestation_requested) {
    return 'Device re-admitted to quarantine; re-attestation was requested and a passing verdict restores it.';
  }
  return 'Device re-admitted to quarantine; it is restored once it passes attestation.';
}
