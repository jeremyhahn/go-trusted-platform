/**
 * Unit check of the real-server harness files, without a browser or a server:
 *
 *   node web/e2e/real-server/specs.check.ts
 *
 * (Node strips the types.) The test daemon config must point the embedded
 * server's AAGUID gate at the allowlist global-setup writes, and every browser
 * context auth.spec.ts creates by hand must carry the fixture base URL.
 * Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'fixtures', 'soft-authenticator.ts');
const sa: typeof import('./fixtures/soft-authenticator') = await import(modPath);

const config = fs.readFileSync(path.join(import.meta.dirname, 'platformd.test.yaml'), 'utf8');
const want = `  webauthn-aaguid-allowlist-file: webauthn-attestation/${sa.ATTESTATION_FILES.aaguidAllowlist}`;
assert.ok(config.split('\n').includes(want), `platformd.test.yaml carries "${want}"`);
assert.ok(config.split('\n').includes('vtpm:'), 'platformd.test.yaml has a vtpm block');
assert.ok(config.split('\n').includes('  base-dir: trusted-data/vtpm'), 'the vtpm base-dir sits in the run directory');

const spec = fs.readFileSync(path.join(import.meta.dirname, 'auth.spec.ts'), 'utf8');
const calls = [...spec.matchAll(/browser\.newContext\(([^)]*)\)/g)];
assert.ok(calls.length > 0, 'auth.spec.ts creates at least one browser context');
for (const call of calls) {
  assert.match(call[1], /\bbaseURL\b/, `newContext call names baseURL: ${call[0]}`);
}

console.log('specs.check: ok');
