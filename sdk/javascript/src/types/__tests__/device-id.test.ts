/**
 * The id on the device surface is a string, and these say why.
 *
 * The server emits it as a JSON string — `json:"id,string"` on the response
 * types, and `device.ID` after #342 — because the platform mints ids above
 * 2^53 and a JSON number at that magnitude loses precision in JavaScript. The
 * declared client type said `number`, so every numeric operation a caller
 * wrote on it was wrong: `id + 1` concatenates once the value is really a
 * string, and an equality test against a literal is false because the literal
 * itself has already been rounded.
 *
 * These assert runtime behaviour, not the declaration, because a declaration
 * alone is what was wrong before. Refs #329, #342.
 */

import { describe, it, expect } from 'vitest';
import type { Device, DeviceProfile, DeviceTemplate } from '../device.js';

/** 2^53 + 1 — the smallest integer a JavaScript number cannot represent. */
const ABOVE_PRECISION = '9007199254740993';

describe('device id encoding', () => {
  it('survives a parse at a magnitude a JS number cannot hold', () => {
    const parsed = JSON.parse(`{"id":"${ABOVE_PRECISION}","name":"lab-node-1"}`) as Device;
    expect(parsed.id).toBe(ABOVE_PRECISION);

    // The control, and the defect this change exists for: the same value sent
    // as a JSON *number* is silently rounded on the way in.
    const asNumber = JSON.parse(`{"id":${ABOVE_PRECISION}}`) as { id: number };
    expect(asNumber.id).toBe(9007199254740992);
    expect(String(asNumber.id)).not.toBe(ABOVE_PRECISION);
  });

  it('round-trips unchanged through stringify', () => {
    const profile = { id: ABOVE_PRECISION, name: 'web-01' } as DeviceProfile;
    const round = JSON.parse(JSON.stringify(profile)) as DeviceProfile;

    expect(round.id).toBe(ABOVE_PRECISION);
    expect(typeof round.id).toBe('string');
  });

  it('is a string on every device type that carries one', () => {
    // Compile-time assertions: each fails to typecheck if a declaration
    // regresses to `number`. The runtime check is incidental.
    const device: Pick<Device, 'id'> = { id: ABOVE_PRECISION };
    const profile: Pick<DeviceProfile, 'id'> = { id: ABOVE_PRECISION };
    const template: Pick<DeviceTemplate, 'id'> = { id: ABOVE_PRECISION };

    for (const v of [device, profile, template]) {
      expect(typeof v.id).toBe('string');
    }
  });

  it('distinguishes two ids that are equal as numbers', () => {
    // The operation that was silently wrong. Two distinct ids one apart at
    // this magnitude compare EQUAL as numbers and differ as strings.
    const a = ABOVE_PRECISION;
    const b = '9007199254740992';

    expect(a).not.toBe(b);
    expect(Number(a) === Number(b)).toBe(true);
  });
});
