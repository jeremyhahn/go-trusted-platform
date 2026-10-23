import { describe, expect, it } from 'vitest';

import { deviceDisableConfirmation, deviceToggle, deviceToggleSuccess } from './device-lifecycle';

// #250: the console offers the transition the control plane can take from
// the device's recorded lifecycle state, and words the result truthfully.

describe('deviceToggle', () => {
  it('offers Enable for a suspended device', () => {
    expect(deviceToggle('suspended')).toBe('enable');
  });

  it('offers no transition for a revoked device', () => {
    expect(deviceToggle('revoked')).toBeNull();
  });

  it('offers Disable for every other state, leaving the decision to the server', () => {
    for (const state of ['attested', 'quarantined', 'pending', 'active', '', undefined]) {
      expect(deviceToggle(state)).toBe('disable');
    }
  });
});

describe('deviceToggleSuccess', () => {
  const result = {
    device_id: '7',
    state: 'quarantined',
    previous_state: 'suspended',
    reattestation_requested: true,
  };

  it('says a disabled device is cut off', () => {
    expect(deviceToggleSuccess('disable', { ...result, state: 'suspended' })).toMatch(/switch port is blocked/);
  });

  it('never tells the operator an enabled device is back in service', () => {
    expect(deviceToggleSuccess('enable', result)).toMatch(/quarantine; re-attestation was requested/);
    expect(deviceToggleSuccess('enable', { ...result, reattestation_requested: false })).toMatch(
      /quarantine; it is restored once it passes attestation/
    );
  });
});

describe('deviceDisableConfirmation', () => {
  it('names the device and the consequence', () => {
    expect(deviceDisableConfirmation('node-07')).toMatch(/^Disable node-07\? Its switch port is blocked/);
  });
});
