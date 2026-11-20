/**
 * Unit check of soft-authenticator.ts, without a browser or a server:
 *
 *   node web/e2e/real-server/fixtures/soft-authenticator.check.ts
 *
 * (Node strips the types.) It generates the attestation CA into a temp dir
 * and checks what the server's packed-attestation verifier needs: x5c[0]
 * chains to the root, the root is CA:TRUE, the leaf is CA:FALSE with OU
 * "Authenticator Attestation" and the AAGUID extension equal to the
 * authData AAGUID, the attestation signature verifies over authData ||
 * SHA-256(clientDataJSON) and the COSE key is the credential key the
 * assertion verifies with. Exits non-zero on the first failure.
 */
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// A computed specifier: tsc (the web typecheck) does not resolve it, so the
// `.ts` extension Node needs is not a TS5097 error there.
const modPath = path.join(import.meta.dirname, 'soft-authenticator.ts');
const sa: typeof import('./soft-authenticator') = await import(modPath);

type Cbor = number | string | boolean | Buffer | Cbor[] | Map<Cbor, Cbor>;

/** A minimal CBOR decoder (definite lengths only), the encoder's mirror. */
function decode(buf: Buffer): Cbor {
  let off = 0;
  const arg = (info: number): number => {
    if (info < 24) return info;
    const n = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0;
    assert.ok(n > 0, `cbor: unsupported additional info ${info}`);
    const v = buf.readUIntBE(off, n);
    off += n;
    return v;
  };
  const item = (): Cbor => {
    const b = buf[off++];
    const major = b >> 5;
    if (major === 7) {
      assert.ok(b === 0xf4 || b === 0xf5, 'cbor: unsupported simple value');
      return b === 0xf5;
    }
    const n = arg(b & 0x1f);
    switch (major) {
      case 0:
        return n;
      case 1:
        return -1 - n;
      case 2:
      case 3: {
        const s = buf.subarray(off, off + n);
        off += n;
        return major === 2 ? Buffer.from(s) : s.toString('utf8');
      }
      case 4:
        return Array.from({ length: n }, item);
      case 5: {
        const m = new Map<Cbor, Cbor>();
        for (let i = 0; i < n; i++) {
          const k = item();
          m.set(k, item());
        }
        return m;
      }
      default:
        throw new Error(`cbor: unsupported major type ${major}`);
    }
  };
  const v = item();
  assert.equal(off, buf.length, 'cbor: trailing bytes');
  return v;
}

const sha256 = (b: Buffer | string) => crypto.createHash('sha256').update(b).digest();
const u = (s: string) => Buffer.from(s, 'base64url');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'soft-authn-check-'));
try {
  // CBOR encoder: canonical integers, strings and the head lengths.
  assert.equal(sa.cborEncode(23).toString('hex'), '17');
  assert.equal(sa.cborEncode(24).toString('hex'), '1818');
  assert.equal(sa.cborEncode(-7).toString('hex'), '26');
  assert.equal(sa.cborEncode(1000).toString('hex'), '1903e8');
  assert.equal(sa.cborEncode('fmt').toString('hex'), '63666d74');
  assert.equal(sa.cborEncode(Buffer.alloc(300)).subarray(0, 3).toString('hex'), '59012c');

  const att = sa.generateAttestationCA(dir);
  assert.deepEqual(fs.readdirSync(dir).sort(), Object.values(sa.ATTESTATION_FILES).sort(), 'only the four run files remain');

  // The chain the server verifies.
  const root = new crypto.X509Certificate(fs.readFileSync(path.join(dir, sa.ATTESTATION_FILES.roots)));
  const leaf = new crypto.X509Certificate(att.leafDer);
  assert.ok(root.ca, 'root is CA:TRUE');
  assert.ok(root.verify(root.publicKey), 'root is self-signed');
  assert.ok(!leaf.ca, 'leaf is CA:FALSE');
  assert.ok(leaf.checkIssued(root) && leaf.verify(root.publicKey), 'leaf chains to the root');
  assert.match(leaf.subject, /OU=Authenticator Attestation/);
  assert.equal(leaf.publicKey.asymmetricKeyDetails?.namedCurve, 'prime256v1');
  // id-fido-gen-ce-aaguid DER: OID 06 0b 2b0601040182e51c010104, then the
  // extnValue OCTET STRING wrapping OCTET STRING(16) = the AAGUID.
  const ext = Buffer.concat([Buffer.from('060b2b0601040182e51c0101040412' + '0410', 'hex'), att.aaguid]);
  assert.ok(att.leafDer.includes(ext), 'leaf carries the AAGUID extension');

  // Registration: packed attestation.
  const auth = new sa.SoftAuthenticator(att);
  const create = auth.makeCredential({
    origin: 'https://localhost:18443',
    rpId: 'localhost',
    challenge: Buffer.from('reg-challenge').toString('base64url'),
    userId: Buffer.from('user-1').toString('base64url'),
    algs: [-7, -257],
    excludeCredentials: [],
  });
  assert.ok(!('error' in create), JSON.stringify(create));
  const obj = decode(u(create.attestationObject)) as Map<Cbor, Cbor>;
  assert.deepEqual([...obj.keys()], ['fmt', 'attStmt', 'authData']);
  assert.equal(obj.get('fmt'), 'packed');
  const stmt = obj.get('attStmt') as Map<Cbor, Cbor>;
  assert.deepEqual([...stmt.keys()], ['alg', 'sig', 'x5c']);
  assert.equal(stmt.get('alg'), -7);
  assert.deepEqual(stmt.get('x5c'), [att.leafDer]);
  const authData = obj.get('authData') as Buffer;
  const clientData = u(create.clientDataJSON);
  assert.deepEqual(JSON.parse(clientData.toString()), {
    type: 'webauthn.create',
    challenge: Buffer.from('reg-challenge').toString('base64url'),
    origin: 'https://localhost:18443',
    crossOrigin: false,
  });
  assert.ok(
    crypto.verify('sha256', Buffer.concat([authData, sha256(clientData)]), leaf.publicKey, stmt.get('sig') as Buffer),
    'attestation signature verifies with the leaf key',
  );
  assert.deepEqual(authData.subarray(0, 32), sha256('localhost'), 'rpIdHash');
  assert.equal(authData[32], 0x45, 'flags UP|UV|AT');
  assert.deepEqual(authData.subarray(37, 53), att.aaguid, 'authData AAGUID = leaf AAGUID');
  const idLen = authData.readUInt16BE(53);
  const credId = authData.subarray(55, 55 + idLen);
  assert.equal(credId.toString('base64url'), create.id);
  const cose = decode(authData.subarray(55 + idLen) as Buffer) as Map<Cbor, Cbor>;
  assert.deepEqual([...cose.keys()], [1, 3, -1, -2, -3]);
  const credPub = crypto.createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: (cose.get(-2) as Buffer).toString('base64url'),
      y: (cose.get(-3) as Buffer).toString('base64url'),
    },
  });
  assert.deepEqual(credPub.export({ type: 'spki', format: 'der' }), u(create.publicKey));

  // excludeCredentials holding it: InvalidStateError.
  const again = auth.makeCredential({
    origin: 'https://localhost:18443',
    rpId: 'localhost',
    challenge: 'AA',
    userId: 'AA',
    algs: [-7],
    excludeCredentials: [create.id],
  });
  assert.equal('error' in again && again.error.name, 'InvalidStateError');

  // Login: usernameless assertion with the credential key.
  const get = auth.getAssertion({
    origin: 'https://localhost:18443',
    rpId: 'localhost',
    challenge: Buffer.from('login-challenge').toString('base64url'),
    allowCredentials: [],
  });
  assert.ok(!('error' in get), JSON.stringify(get));
  assert.equal(get.id, create.id);
  assert.equal(get.userHandle, Buffer.from('user-1').toString('base64url'));
  const ad = u(get.authenticatorData);
  assert.equal(ad.length, 37);
  assert.equal(ad[32], 0x05, 'flags UP|UV');
  assert.ok(ad.readUInt32BE(33) > authData.readUInt32BE(33), 'signCount grows');
  assert.ok(
    crypto.verify('sha256', Buffer.concat([ad, sha256(u(get.clientDataJSON))]), credPub, u(get.signature)),
    'assertion verifies with the credential key',
  );

  // Another relying party, or a fresh authenticator: NotAllowedError.
  const other = auth.getAssertion({ origin: 'https://x', rpId: 'example.com', challenge: 'AA', allowCredentials: [] });
  assert.equal('error' in other && other.error.name, 'NotAllowedError');
  const empty = new sa.SoftAuthenticator(att).getAssertion({
    origin: 'https://localhost:18443',
    rpId: 'localhost',
    challenge: 'AA',
    allowCredentials: [],
  });
  assert.equal('error' in empty && empty.error.name, 'NotAllowedError');

  console.log('soft-authenticator check: ok');
} finally {
  fs.rmSync(dir, { recursive: true, force: true });
}
