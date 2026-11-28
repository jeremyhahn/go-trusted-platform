import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

/*
 * Stored manifests the real-server specs act on (#2038, UI epic #1665).
 *
 * BuildManifest needs a daemon-managed TPM session the real-server daemon
 * does not have (ErrTPMSessionNotConfigured), so global-setup writes these
 * manifests into the attestation FileStore before platformd starts. The
 * store root is <run dir>/trusted-data/attestation (platformd.test.yaml
 * platform-dir), one <id>.json per manifest under manifests/, in
 * json.MarshalIndent's shape of pkg/attestation/manifest HostManifest: Go
 * field names (no json tags), []byte as base64, time.Time as RFC 3339.
 */

/** The seeded manifests: the verify spec verifies one, the delete spec deletes the other. */
export const SEEDED_MANIFESTS = {
  verify: { id: 'e2e-seed-verify', hostId: 'e2e-seed-verify-host' },
  delete: { id: 'e2e-seed-delete', hostId: 'e2e-seed-delete-host' },
} as const;

/** The on-disk HostManifest of one seeded entry, fresh nonce and Merkle root. */
function storedManifest(entry: { id: string; hostId: string }) {
  return {
    ID: entry.id,
    HostID: entry.hostId,
    Timestamp: new Date().toISOString(),
    Nonce: randomBytes(32).toString('base64'),
    Host: null,
    VMs: null,
    Containers: null,
    MerkleRoot: randomBytes(32).toString('base64'),
    Signature: null,
    SignatureAlgorithm: '',
    Version: '1.0',
    Metadata: { source: 'e2e-seed' },
  };
}

/** Writes every SEEDED_MANIFESTS entry into runDir's attestation FileStore. */
export function seedManifests(runDir: string): void {
  const manifestsDir = path.join(runDir, 'trusted-data', 'attestation', 'manifests');
  fs.mkdirSync(manifestsDir, { recursive: true, mode: 0o700 });
  for (const entry of Object.values(SEEDED_MANIFESTS)) {
    const file = path.join(manifestsDir, `${entry.id}.json`);
    fs.writeFileSync(file, JSON.stringify(storedManifest(entry), null, 2), { mode: 0o600 });
  }
}
