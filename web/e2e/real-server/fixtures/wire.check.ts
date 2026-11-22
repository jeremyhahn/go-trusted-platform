/**
 * Unit check of wire.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/wire.check.ts
 *
 * (Node strips the types.) The REST API answers every call in a
 * {code, success, error, payload} envelope, and protojson writes int64 and
 * uint64 fields as decimal strings: unwrapPayload must return the payload
 * and refuse an error envelope, wireCount must read either form and refuse
 * anything that is not a non-negative safe integer. Exits non-zero on the
 * first failure.
 */
import assert from 'node:assert/strict';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'wire.ts');
const wire: typeof import('./wire') = await import(modPath);

// unwrapPayload: the payload of a success envelope.
assert.deepEqual(wire.unwrapPayload({ code: 200, success: true, payload: { a: 1 } }), { a: 1 });

// An error envelope, or one without a payload, throws naming its error.
assert.throws(
  () => wire.unwrapPayload({ code: 403, success: false, error: 'permission denied' }),
  (e: unknown) => e instanceof Error && e.message.includes('permission denied'),
  'success:false throws with the error text',
);
assert.throws(
  () => wire.unwrapPayload({ code: 200, success: true, error: 'no payload here' }),
  (e: unknown) => e instanceof Error && e.message.includes('no payload here'),
  'a missing payload throws with the error text',
);
assert.throws(() => wire.unwrapPayload(null), Error, 'null is not an envelope');
assert.throws(() => wire.unwrapPayload([1]), Error, 'an array is not an envelope');

// wireCount: numbers and protojson decimal strings.
assert.equal(wire.wireCount(7), 7);
assert.equal(wire.wireCount(0), 0);
assert.equal(wire.wireCount('42'), 42);
assert.throws(() => wire.wireCount('18446744073709551615'), Error, 'beyond Number.MAX_SAFE_INTEGER');
assert.throws(() => wire.wireCount('4x'), Error, 'not a decimal string');
assert.throws(() => wire.wireCount(''), Error, 'empty string');
assert.throws(() => wire.wireCount(-1), Error, 'negative');
assert.throws(() => wire.wireCount(1.5), Error, 'not an integer');
assert.throws(() => wire.wireCount(undefined), Error, 'missing');

console.log('wire check: ok');
