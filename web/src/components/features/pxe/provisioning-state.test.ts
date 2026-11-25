import { describe, expect, it } from 'vitest';

import { provisioningStateName } from './provisioning-state';

// #2062: the REST server writes enum names (PROVISIONING_STATE_DISCOVERED);
// the PXE pages key their stats and badge colours on the short name.
describe('provisioningStateName', () => {
  it('strips the protobuf enum prefix', () => {
    expect(provisioningStateName('PROVISIONING_STATE_DISCOVERED')).toBe('DISCOVERED');
  });

  it('keeps a short name as it is', () => {
    expect(provisioningStateName('ENROLLED')).toBe('ENROLLED');
  });

  it('reads a missing state as UNKNOWN', () => {
    expect(provisioningStateName(undefined)).toBe('UNKNOWN');
    expect(provisioningStateName('')).toBe('UNKNOWN');
  });
});
