/**
 * Unit check of vtpm-wire.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/vtpm-wire.check.ts
 *
 * (Node strips the types.) GET /api/v1/capabilities and
 * GET /api/v1/vtpm/bundles/{id}/state answer in the {code, success, payload}
 * envelope: enabledOpsFrom must read payload.capabilities and runStateFrom
 * payload.running, and both must refuse an error envelope or a malformed
 * reply instead of defaulting to an empty list or a stopped state. Exits
 * non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'vtpm-wire.ts');
const vw: typeof import('./vtpm-wire') = await import(modPath);

const STATE_OP = 'GET /api/v1/vtpm/bundles/{id}/state';
const START_OP = 'POST /api/v1/vtpm/bundles/{id}/start';

// enabledOpsFrom: the enabled ops of the listing's payload.
const ops = vw.enabledOpsFrom({
  code: 200,
  success: true,
  payload: {
    capabilities: [
      { op: STATE_OP, kind: 'route', enabled: true },
      { op: START_OP, kind: 'route', enabled: false },
    ],
    total: 2,
    enabled: 1,
  },
});
assert.ok(ops instanceof Set, 'enabledOpsFrom returns a Set');
assert.deepEqual([...ops], [STATE_OP], 'only the enabled op is listed');

// An error envelope throws naming its error.
assert.throws(
  () => vw.enabledOpsFrom({ code: 403, success: false, error: 'permission denied' }),
  (e: unknown) => e instanceof Error && e.message.includes('permission denied'),
  'an error envelope throws with the error text',
);
// A top-level listing with no envelope is not the server's reply.
assert.throws(
  () => vw.enabledOpsFrom({ capabilities: [{ op: STATE_OP, kind: 'route', enabled: true }] }),
  Error,
  'a listing outside the envelope throws',
);
// A payload without a capabilities array.
assert.throws(() => vw.enabledOpsFrom({ code: 200, success: true, payload: { total: 0 } }), Error, 'no capabilities');
assert.throws(
  () => vw.enabledOpsFrom({ code: 200, success: true, payload: { capabilities: 'none' } }),
  Error,
  'capabilities is not an array',
);
// An entry whose op is not a string, or whose enabled is not a boolean.
assert.throws(
  () => vw.enabledOpsFrom({ code: 200, success: true, payload: { capabilities: [{ op: 7, enabled: true }] } }),
  Error,
  'op is not a string',
);
assert.throws(
  () => vw.enabledOpsFrom({ code: 200, success: true, payload: { capabilities: [{ op: STATE_OP, enabled: 'true' }] } }),
  Error,
  'enabled is not a boolean',
);
assert.throws(
  () => vw.enabledOpsFrom({ code: 200, success: true, payload: { capabilities: [{ op: STATE_OP }] } }),
  Error,
  'enabled is missing',
);

// runStateFrom: payload.running of the state reply.
assert.equal(vw.runStateFrom({ code: 200, success: true, payload: { id: 'b1', running: true } }), true);
assert.equal(vw.runStateFrom({ code: 200, success: true, payload: { id: 'b1', running: false } }), false);
assert.throws(() => vw.runStateFrom({ code: 200, success: true, payload: { id: 'b1' } }), Error, 'running is missing');
assert.throws(
  () => vw.runStateFrom({ code: 200, success: true, payload: { id: 'b1', running: 'true' } }),
  Error,
  'running is not a boolean',
);
assert.throws(
  () => vw.runStateFrom({ code: 404, success: false, error: 'bundle not found' }),
  (e: unknown) => e instanceof Error && e.message.includes('bundle not found'),
  'an error envelope throws with the error text',
);
assert.throws(() => vw.runStateFrom({ id: 'b1', running: true }), Error, 'a state outside the envelope throws');

console.log('vtpm-wire check: ok');
