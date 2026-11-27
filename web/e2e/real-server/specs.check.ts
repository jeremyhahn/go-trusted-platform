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

const vtpmSpec = fs.readFileSync(path.join(import.meta.dirname, 'vtpm-runtime.spec.ts'), 'utf8');
assert.ok(
  vtpmSpec.includes("test('drives a running bundle through every runtime control'"),
  'vtpm-runtime.spec.ts has the runtime flow test',
);

const spec = fs.readFileSync(path.join(import.meta.dirname, 'auth.spec.ts'), 'utf8');
const calls = [...spec.matchAll(/browser\.newContext\(([^)]*)\)/g)];
assert.ok(calls.length > 0, 'auth.spec.ts creates at least one browser context');
for (const call of calls) {
  assert.match(call[1], /\bbaseURL\b/, `newContext call names baseURL: ${call[0]}`);
}

// The seeded registry spec (#2063) runs against the real platformd: it seeds
// its images with the /v2 push fixture and the real-server fixtures, never a
// page.route mock or api-mock, and every context it opens names baseURL.
const registry = fs.readFileSync(path.join(import.meta.dirname, 'registry-seeded.spec.ts'), 'utf8');
assert.match(
  registry,
  /import\s*\{[^}]*\bpushTestImage\b[^}]*\}\s*from\s*'\.\/fixtures\/registry-seed'/,
  'registry-seeded.spec.ts imports pushTestImage from ./fixtures/registry-seed',
);
assert.match(
  registry,
  /import\s*\{[^}]*\brequestFetch\b[^}]*\}\s*from\s*'\.\/fixtures'/,
  'registry-seeded.spec.ts imports requestFetch from ./fixtures',
);
assert.match(
  registry,
  /import\s*\{[^}]*\btest\b[^}]*\}\s*from\s*'\.\/fixtures'/,
  'registry-seeded.spec.ts imports test from ./fixtures',
);
assert.doesNotMatch(registry, /page\.route\(/, 'registry-seeded.spec.ts mocks no route with page.route(');
assert.doesNotMatch(registry, /api-mock/, 'registry-seeded.spec.ts does not use api-mock');
for (const call of registry.matchAll(/browser\.newContext\(([^)]*)\)/g)) {
  assert.match(call[1], /\bbaseURL\b/, `registry-seeded.spec.ts newContext call names baseURL: ${call[0]}`);
}

// The seeded spec inspects a real pushed tag through the page's own
// GET /api/v1/compute/images/... and asserts the OCI capability gates.
assert.match(registry, /registry-inspect-panel/, 'registry-seeded.spec.ts asserts the registry-inspect-panel');
assert.match(
  registry,
  /startsWith\('\/api\/v1\/compute\/images\/'\)/,
  'registry-seeded.spec.ts waits for the page\'s own /api/v1/compute/images/ response',
);
assert.match(registry, /data-capability-op/, 'registry-seeded.spec.ts asserts data-capability-op');
assert.match(
  registry,
  /DELETE \/v2\/\{name:\.\+\}\/manifests\/\{reference\}/,
  'registry-seeded.spec.ts asserts the DELETE /v2/{name:.+}/manifests/{reference} gate',
);
assert.match(
  registry,
  /GET \/v2\/\{name:\.\+\}\/tags\/list/,
  'registry-seeded.spec.ts asserts the GET /v2/{name:.+}/tags/list gate',
);

console.log('specs.check: ok');
