/**
 * The provisioning session is a snake_case wire, and these say why the client
 * declares exactly that.
 *
 * `pkg/provisioning/configdelivery/types.go` `Session` emits `ek_serial`,
 * `mac_address`, `tenant_id`, `profile_id`, `profile`, `fulfilled`,
 * `created_at`, `expires_at`. Until #425 the SDK declared `ekSerial`,
 * `macAddress`, `tenantId`, `profileId: number`, `createdAt`, `expiresAt` —
 * so every read on the console's session pages was `undefined` ("Not
 * reported" for a serial the server sent, an invalid date for a real expiry)
 * and typechecked perfectly. The fixture is the Go struct's JSON; the Go-side
 * ratchet (`session_wire_parity_test.go`) pins the declaration to the tags.
 */

import { describe, it, expect } from 'vitest';
import type { ProvisioningSession } from '../device.js';

/** A fulfilled session exactly as GET /v1/provisioning/sessions/{id} emits it. */
const WIRE = `{
  "id": "sess-7",
  "ek_serial": "EK-0001",
  "mac_address": "52:54:00:aa:bb:cc",
  "tenant_id": "tenant-1",
  "profile_id": "9007199254740993",
  "profile": { "id": "9007199254740993", "name": "lab-worker", "role": "worker" },
  "fulfilled": true,
  "created_at": "2026-09-05T10:00:00Z",
  "expires_at": "2026-09-05T10:30:00Z"
}`;

describe('provisioning session wire', () => {
  it('decodes every field the server sends, under the name it sends it', () => {
    const session = JSON.parse(WIRE) as ProvisioningSession;

    expect(session.ek_serial).toBe('EK-0001');
    expect(session.mac_address).toBe('52:54:00:aa:bb:cc');
    expect(session.tenant_id).toBe('tenant-1');
    expect(session.fulfilled).toBe(true);
    expect(new Date(session.expires_at).getTime()).toBeGreaterThan(
      new Date(session.created_at).getTime()
    );
    expect(session.profile?.name).toBe('lab-worker');
  });

  it('keeps the profile id exact above 2^53 because the wire is a string', () => {
    const session = JSON.parse(WIRE) as ProvisioningSession;
    expect(session.profile_id).toBe('9007199254740993');
    expect(typeof session.profile_id).toBe('string');

    // The control: the same value as a JSON number is silently rounded on the
    // way in — which is what the pre-#425 `profileId: number` promised callers.
    const rounded = JSON.parse('{"profile_id": 9007199254740993}') as { profile_id: number };
    expect(String(rounded.profile_id)).not.toBe('9007199254740993');
  });

  it('has no camelCase declaration left for a snake_case wire name', () => {
    // Compile-time: each fails to typecheck if the old spelling is reintroduced.
    type Old = Extract<
      keyof ProvisioningSession,
      'ekSerial' | 'macAddress' | 'tenantId' | 'profileId' | 'createdAt' | 'expiresAt'
    >;
    const none: [Old] extends [never] ? true : false = true;
    expect(none).toBe(true);

    // Runtime: a read under the old spelling is undefined against the real body.
    const session = JSON.parse(WIRE) as unknown as { ekSerial?: string; ek_serial?: string };
    expect(session.ekSerial).toBeUndefined();
    expect(session.ek_serial).toBe('EK-0001');
  });

  it('treats a pending session as complete without the optional fields', () => {
    const pending = JSON.parse(
      '{"id":"sess-8","fulfilled":false,"created_at":"2026-09-05T10:00:00Z","expires_at":"2026-09-05T10:30:00Z"}'
    ) as ProvisioningSession;
    expect(pending.ek_serial).toBeUndefined();
    expect(pending.profile_id).toBeUndefined();
    expect(pending.profile).toBeUndefined();
    expect(pending.fulfilled).toBe(false);
  });
});
