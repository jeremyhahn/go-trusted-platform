/**
 * Unit check of seed-manifests.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/seed-manifests.check.ts
 *
 * (Node strips the types.) BuildManifest needs a daemon-managed TPM session
 * the real-server daemon has not, so global-setup writes the manifests the
 * verify and delete specs act on straight into the attestation FileStore
 * before platformd starts. The files must be in the FileStore's on-disk
 * shape (pkg/attestation/manifest/types.go HostManifest: Go field names,
 * []byte as base64, time as RFC 3339) at
 * <run dir>/trusted-data/attestation/manifests/<id>.json. Exits non-zero on
 * the first failure.
 */
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'seed-manifests.ts');
const seed: typeof import('./seed-manifests') = await import(modPath);

// (a) a verify and a delete entry, distinct, each id one path segment.
const entries = [seed.SEEDED_MANIFESTS.verify, seed.SEEDED_MANIFESTS.delete];
for (const e of entries) {
  assert.ok(e, 'SEEDED_MANIFESTS has a verify and a delete entry');
  assert.equal(typeof e.id, 'string');
  assert.equal(typeof e.hostId, 'string');
  assert.ok(e.id.length > 0 && e.hostId.length > 0, 'non-empty id and hostId');
  assert.ok(
    !e.id.includes('/') && !e.id.includes('\\') && !e.id.includes('..') && !e.id.includes('\0'),
    `manifest id ${e.id} is one path segment`,
  );
}
assert.notEqual(seed.SEEDED_MANIFESTS.verify.id, seed.SEEDED_MANIFESTS.delete.id, 'distinct ids');
assert.notEqual(seed.SEEDED_MANIFESTS.verify.hostId, seed.SEEDED_MANIFESTS.delete.hostId, 'distinct hostIds');

// (b) seedManifests writes both files under the FileStore root.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seed-check-'));
try {
  seed.seedManifests(dir);
  const base64 = /^[A-Za-z0-9+/]+={0,2}$/;
  const rfc3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
  for (const e of entries) {
    const file = path.join(dir, 'trusted-data', 'attestation', 'manifests', `${e.id}.json`);
    assert.ok(fs.existsSync(file), `${file} is written`);

    // (c) the Go field names and encodings.
    const m = JSON.parse(fs.readFileSync(file, 'utf8')) as Record<string, unknown>;
    assert.equal(m.ID, e.id);
    assert.equal(m.HostID, e.hostId);
    assert.equal(typeof m.Timestamp, 'string');
    assert.match(m.Timestamp as string, rfc3339, 'Timestamp is RFC 3339');
    const age = Math.abs(Date.now() - Date.parse(m.Timestamp as string));
    assert.ok(age < 60_000, `Timestamp within 60 s of now (off by ${age} ms)`);
    for (const k of ['Nonce', 'MerkleRoot']) {
      assert.equal(typeof m[k], 'string', `${k} is a base64 string`);
      assert.ok((m[k] as string).length > 0, `${k} is non-empty`);
      assert.match(m[k] as string, base64, `${k} is base64`);
    }
    assert.equal(m.Version, '1.0');
    assert.deepEqual(m.Metadata, { source: 'e2e-seed' });
  }
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}

// (d) global-setup seeds the run dir before platformd is spawned.
const setup = fs.readFileSync(path.join(import.meta.dirname, '..', 'global-setup.ts'), 'utf8');
assert.match(
  setup,
  /import \{[^}]*\bseedManifests\b[^}]*\} from '\.\/fixtures\/seed-manifests';/,
  'global-setup imports seedManifests',
);
const call = setup.indexOf('seedManifests(dir);');
const spawnAt = setup.indexOf('spawn(binary');
assert.ok(call >= 0, 'global-setup calls seedManifests(dir)');
assert.ok(spawnAt >= 0, 'global-setup spawns platformd');
assert.ok(call < spawnAt, 'seedManifests(dir) runs before the spawn( call');

console.log('seed-manifests.check: ok');
