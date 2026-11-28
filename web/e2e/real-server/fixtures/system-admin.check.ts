/**
 * Unit check of system-admin.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/system-admin.check.ts
 *
 * (Node strips the types.) The proxy API is system-tenant only, so the
 * real-server specs sign in as the system admin through the admin claim
 * ceremony (docs/auth/api.md). This pins its pure parts: where the claim
 * bundle sits in the run dir, where the session is persisted, the challenge
 * signature for ECDSA P-256, RSA 2048 and Ed25519 keys (SHA-256 for ECDSA
 * and RSA PKCS#1 v1.5, raw for Ed25519, as the server's ProveRequest
 * verifies it) and the verify body. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'system-admin.ts');
const sa: typeof import('./system-admin') = await import(modPath);

// The claim bundle and the session file live in the run dir.
assert.deepEqual(sa.adminBundlePaths('/r'), {
  cert: '/r/trusted-data/quicbaas/admin/admin.crt',
  key: '/r/trusted-data/quicbaas/admin/admin.key',
});
assert.equal(sa.systemSessionFile('/r'), '/r/system-admin-session.json');

// The challenge signature verifies for each key type the server accepts.
const challenge = 'Y2hhbGxlbmdl';
// The server verifies over the challenge string as sent, not its decoding
// (service.go: verifyChallengeSignature(cert, []byte(req.Challenge), ...)).
const challengeBytes = Buffer.from(challenge, 'utf8');
const pemPair = (kp: crypto.KeyPairKeyObjectResult) => ({
  priv: kp.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
  pub: kp.publicKey,
});
const cases: Array<{ name: string; alg: string | null; kp: crypto.KeyPairKeyObjectResult }> = [
  { name: 'ECDSA P-256', alg: 'sha256', kp: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }) },
  { name: 'RSA 2048', alg: 'sha256', kp: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }) },
  { name: 'Ed25519', alg: null, kp: crypto.generateKeyPairSync('ed25519') },
];
for (const c of cases) {
  const { priv, pub } = pemPair(c.kp);
  const sig = sa.signClaimChallenge(priv, challenge);
  assert.match(sig, /^[A-Za-z0-9+/]+=*$/, `${c.name}: the signature is base64`);
  assert.ok(
    crypto.verify(c.alg, challengeBytes, pub, Buffer.from(sig, 'base64')),
    `${c.name}: the signature verifies over the challenge bytes`,
  );
}

// The verify body carries exactly the challenge, the certificate and the signature.
{
  const { priv } = pemPair(cases[0].kp);
  const body = sa.proveBody(challenge, 'CERT-PEM', priv);
  assert.deepEqual(Object.keys(body).sort(), ['certificate_pem', 'challenge', 'signature']);
  assert.equal(body.challenge, challenge);
  assert.equal(body.certificate_pem, 'CERT-PEM');
  assert.ok(
    crypto.verify('sha256', challengeBytes, cases[0].kp.publicKey, Buffer.from(body.signature, 'base64')),
    'the verify body signature verifies',
  );
}

console.log('system-admin check: ok');
