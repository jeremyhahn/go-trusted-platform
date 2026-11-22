import { execFileSync } from 'child_process';
import crypto, { type KeyObject } from 'crypto';
import fs from 'fs';
import path from 'path';
import type { BrowserContext, Page } from '@playwright/test';

/**
 * A software WebAuthn authenticator for the real-server e2e (#2034, epic
 * #1665; Tenant Agent ruling 1028 Q1 (c)).
 *
 * The server admits an administrative WebAuthn enrollment only with an
 * attestation that chains to a trusted root. Chromium's CDP virtual
 * authenticator attests with a self-signed CA:FALSE batch certificate, which
 * is refused as an anchor. So the suite signs its own attestation:
 *
 *  - generateAttestationCA (global-setup) makes, at run time and into the
 *    run's temp dir, a test root CA and a FIDO batch attestation leaf it
 *    signs. The root's file is the server's
 *    quicbaas.webauthn-attestation-roots-file; an allowlist holding the
 *    run's random AAGUID is its quicbaas.webauthn-aaguid-allowlist-file.
 *  - SoftAuthenticator answers navigator.credentials.create/get on a page
 *    (exposeBinding + addInitScript): a P-256 credential, a `packed`
 *    attestation with x5c = [leaf] signed by the leaf key, and ES256
 *    assertions signed by the credential key.
 *
 * No key or certificate is committed: every one is generated per run.
 */

// ---------------------------------------------------------------------------
// Attestation CA
// ---------------------------------------------------------------------------

/** File names generateAttestationCA writes into its directory. */
export const ATTESTATION_FILES = {
  roots: 'roots.pem',
  leafCert: 'leaf.pem',
  leafKey: 'leaf.key',
  aaguid: 'aaguid.hex',
  aaguidAllowlist: 'aaguid-allowlist.json',
} as const;

/** id-fido-gen-ce-aaguid: the batch certificate names the authenticator model. */
export const FIDO_AAGUID_OID = '1.3.6.1.4.1.45724.1.1.4';

/** What the authenticator signs its attestation with. */
export interface AttestationMaterial {
  /** DER of the batch attestation leaf (x5c[0]). */
  leafDer: Buffer;
  /** The leaf's P-256 private key. */
  leafKey: KeyObject;
  /** The 16-byte AAGUID, equal to the leaf's AAGUID extension. */
  aaguid: Buffer;
}

function pemKey(key: KeyObject): string {
  return key.export({ type: 'pkcs8', format: 'pem' }).toString();
}

/**
 * Generates a test attestation root (CA:TRUE, keyCertSign) and a batch
 * attestation leaf it signs (CA:FALSE, P-256, OU "Authenticator
 * Attestation", the AAGUID extension) into dir with the openssl CLI. The
 * root's private key is removed once the leaf is signed. Returns the
 * material for SoftAuthenticator; the roots file is
 * path.join(dir, ATTESTATION_FILES.roots).
 */
export function generateAttestationCA(dir: string): AttestationMaterial {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const p = (name: string) => path.join(dir, name);
  const aaguid = crypto.randomBytes(16);
  const aaguidHex = aaguid.toString('hex');

  const root = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const leaf = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  fs.writeFileSync(p('root.key'), pemKey(root.privateKey), { mode: 0o600 });
  fs.writeFileSync(p(ATTESTATION_FILES.leafKey), pemKey(leaf.privateKey), { mode: 0o600 });
  fs.writeFileSync(p(ATTESTATION_FILES.aaguid), `${aaguidHex}\n`);
  // The server's AAGUID gate is strict by default: only listed models enroll.
  fs.writeFileSync(
    p(ATTESTATION_FILES.aaguidAllowlist),
    JSON.stringify([{ aaguid: aaguidHex, name: 'E2E Soft Authenticator' }]),
  );
  fs.writeFileSync(
    p('openssl.cnf'),
    [
      '[req]',
      'distinguished_name = dn',
      'prompt = no',
      '[dn]',
      'CN = unused',
      '[root_ext]',
      'basicConstraints = critical, CA:TRUE',
      'keyUsage = critical, keyCertSign, cRLSign',
      'subjectKeyIdentifier = hash',
      '[leaf_ext]',
      'basicConstraints = critical, CA:FALSE',
      'keyUsage = critical, digitalSignature',
      'subjectKeyIdentifier = hash',
      'authorityKeyIdentifier = keyid',
      `${FIDO_AAGUID_OID} = ASN1:FORMAT:HEX,OCTETSTRING:${aaguidHex}`,
      '',
    ].join('\n'),
  );

  const openssl = (args: string[]) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });
  openssl([
    'req', '-x509', '-new', '-sha256', '-days', '7', '-set_serial', '1',
    '-key', 'root.key', '-config', 'openssl.cnf', '-extensions', 'root_ext',
    '-subj', '/C=US/O=Trusted Platform E2E/CN=E2E WebAuthn Attestation Root',
    '-out', ATTESTATION_FILES.roots,
  ]);
  openssl([
    'req', '-new', '-sha256', '-key', ATTESTATION_FILES.leafKey, '-config', 'openssl.cnf',
    '-subj', '/C=US/O=Trusted Platform E2E/OU=Authenticator Attestation/CN=E2E Soft Authenticator',
    '-out', 'leaf.csr',
  ]);
  openssl([
    'x509', '-req', '-sha256', '-days', '7', '-set_serial', '2',
    '-in', 'leaf.csr', '-CA', ATTESTATION_FILES.roots, '-CAkey', 'root.key',
    '-extfile', 'openssl.cnf', '-extensions', 'leaf_ext',
    '-out', ATTESTATION_FILES.leafCert,
  ]);
  for (const f of ['root.key', 'leaf.csr', 'openssl.cnf']) {
    fs.rmSync(p(f), { force: true });
  }
  return loadAttestation(dir);
}

/** Reads the material generateAttestationCA wrote into dir. */
export function loadAttestation(dir: string): AttestationMaterial {
  const p = (name: string) => path.join(dir, name);
  const cert = new crypto.X509Certificate(fs.readFileSync(p(ATTESTATION_FILES.leafCert)));
  return {
    leafDer: cert.raw,
    leafKey: crypto.createPrivateKey(fs.readFileSync(p(ATTESTATION_FILES.leafKey))),
    aaguid: Buffer.from(fs.readFileSync(p(ATTESTATION_FILES.aaguid), 'utf8').trim(), 'hex'),
  };
}

// ---------------------------------------------------------------------------
// Minimal CBOR encoder (RFC 8949): what attestationObject and a COSE key need
// ---------------------------------------------------------------------------

export type CborValue = number | string | boolean | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

function cborHead(major: number, n: number): Buffer {
  const m = major << 5;
  if (n < 24) return Buffer.from([m | n]);
  if (n < 0x100) return Buffer.from([m | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = m | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  if (n < 0x100000000) {
    const b = Buffer.alloc(5);
    b[0] = m | 26;
    b.writeUInt32BE(n, 1);
    return b;
  }
  throw new Error(`cbor: ${n} is out of range`);
}

/**
 * Encodes v. Map keys are written in insertion order: callers insert them
 * in CTAP2 canonical order (shorter encoding first, then bytewise).
 */
export function cborEncode(v: CborValue): Buffer {
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new Error('cbor: only integers are supported');
    return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  }
  if (typeof v === 'boolean') return Buffer.from([v ? 0xf5 : 0xf4]);
  if (typeof v === 'string') {
    const b = Buffer.from(v, 'utf8');
    return Buffer.concat([cborHead(3, b.length), b]);
  }
  if (v instanceof Uint8Array) return Buffer.concat([cborHead(2, v.length), v]);
  if (Array.isArray(v)) return Buffer.concat([cborHead(4, v.length), ...v.map(cborEncode)]);
  if (v instanceof Map) {
    const parts: Buffer[] = [cborHead(5, v.size)];
    for (const [k, val] of v) parts.push(cborEncode(k), cborEncode(val));
    return Buffer.concat(parts);
  }
  throw new Error('cbor: unsupported value');
}

/** The COSE_Key (EC2, ES256) of a P-256 public key. */
export function coseKeyES256(publicKey: KeyObject): Buffer {
  const jwk = publicKey.export({ format: 'jwk' });
  return cborEncode(
    new Map<CborValue, CborValue>([
      [1, 2], // kty: EC2
      [3, -7], // alg: ES256
      [-1, 1], // crv: P-256
      [-2, Buffer.from(jwk.x as string, 'base64url')],
      [-3, Buffer.from(jwk.y as string, 'base64url')],
    ]),
  );
}

// ---------------------------------------------------------------------------
// The authenticator
// ---------------------------------------------------------------------------

/** navigator.credentials.create, as the page script passes it (base64url). */
export interface CreateRequest {
  origin: string;
  rpId: string;
  challenge: string;
  userId: string;
  algs: number[];
  excludeCredentials: string[];
}

/** navigator.credentials.get, as the page script passes it (base64url). */
export interface GetRequest {
  origin: string;
  rpId: string;
  challenge: string;
  allowCredentials: string[];
}

export interface CeremonyError {
  error: { name: string; message: string };
}

export interface CreateResult {
  id: string;
  clientDataJSON: string;
  attestationObject: string;
  authenticatorData: string;
  publicKey: string;
}

export interface GetResult {
  id: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string;
}

interface StoredCredential {
  id: Buffer;
  rpId: string;
  userId: string;
  key: KeyObject;
}

const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_AT = 0x40;
const ES256 = -7;

const b64u = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const sha256 = (b: Uint8Array | string) => crypto.createHash('sha256').update(b).digest();

function fail(name: string, message: string): CeremonyError {
  return { error: { name, message } };
}

/** The binding names the page script calls. */
export const BINDINGS = { create: '__softWebAuthnCreate', get: '__softWebAuthnGet' } as const;

export class SoftAuthenticator {
  private readonly att: AttestationMaterial;
  private readonly credentials: StoredCredential[] = [];
  private signCount = 0;

  constructor(att: AttestationMaterial) {
    this.att = att;
  }

  /** The credentials this authenticator holds (resident keys). */
  get count(): number {
    return this.credentials.length;
  }

  private authData(rpId: string, flags: number, attested?: Buffer): Buffer {
    this.signCount += 1;
    const head = Buffer.alloc(37);
    sha256(rpId).copy(head, 0);
    head[32] = flags;
    head.writeUInt32BE(this.signCount, 33);
    return attested ? Buffer.concat([head, attested]) : head;
  }

  private clientData(type: string, challenge: string, origin: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }), 'utf8');
  }

  /** authenticatorMakeCredential with `packed` full attestation. */
  makeCredential(req: CreateRequest): CreateResult | CeremonyError {
    if (req.algs.length > 0 && !req.algs.includes(ES256)) {
      return fail('NotSupportedError', 'soft authenticator: ES256 not among pubKeyCredParams');
    }
    const excluded = this.credentials.find((c) => c.rpId === req.rpId && req.excludeCredentials.includes(b64u(c.id)));
    if (excluded) {
      return fail('InvalidStateError', 'soft authenticator: a credential in excludeCredentials is present');
    }
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const id = crypto.randomBytes(32);
    const idLen = Buffer.alloc(2);
    idLen.writeUInt16BE(id.length, 0);
    const attested = Buffer.concat([this.att.aaguid, idLen, id, coseKeyES256(publicKey)]);
    const authData = this.authData(req.rpId, FLAG_UP | FLAG_UV | FLAG_AT, attested);
    const clientDataJSON = this.clientData('webauthn.create', req.challenge, req.origin);
    const sig = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.att.leafKey);
    const attestationObject = cborEncode(
      new Map<CborValue, CborValue>([
        ['fmt', 'packed'],
        [
          'attStmt',
          new Map<CborValue, CborValue>([
            ['alg', ES256],
            ['sig', sig],
            ['x5c', [this.att.leafDer]],
          ]),
        ],
        ['authData', authData],
      ]),
    );
    // A resident key: a newer credential for the same user replaces it.
    const prior = this.credentials.findIndex((c) => c.rpId === req.rpId && c.userId === req.userId);
    if (prior >= 0) this.credentials.splice(prior, 1);
    this.credentials.push({ id, rpId: req.rpId, userId: req.userId, key: privateKey });
    return {
      id: b64u(id),
      clientDataJSON: b64u(clientDataJSON),
      attestationObject: b64u(attestationObject),
      authenticatorData: b64u(authData),
      publicKey: b64u(publicKey.export({ type: 'spki', format: 'der' })),
    };
  }

  /** authenticatorGetAssertion; an empty allow list picks the newest resident key. */
  getAssertion(req: GetRequest): GetResult | CeremonyError {
    const candidates = this.credentials.filter(
      (c) => c.rpId === req.rpId && (req.allowCredentials.length === 0 || req.allowCredentials.includes(b64u(c.id))),
    );
    const cred = candidates[candidates.length - 1];
    if (!cred) {
      return fail('NotAllowedError', 'soft authenticator: no credential for this relying party');
    }
    const authData = this.authData(req.rpId, FLAG_UP | FLAG_UV);
    const clientDataJSON = this.clientData('webauthn.get', req.challenge, req.origin);
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), cred.key);
    return {
      id: b64u(cred.id),
      clientDataJSON: b64u(clientDataJSON),
      authenticatorData: b64u(authData),
      signature: b64u(signature),
      userHandle: cred.userId,
    };
  }

  /**
   * Answers navigator.credentials on target (a page, or every page of a
   * context) from the next navigation on.
   */
  async install(target: Page | BrowserContext): Promise<void> {
    await target.exposeBinding(BINDINGS.create, (_src, req: CreateRequest) => this.makeCredential(req));
    await target.exposeBinding(BINDINGS.get, (_src, req: GetRequest) => this.getAssertion(req));
    await target.addInitScript(pageScript, BINDINGS);
  }
}

/**
 * Runs in the page: replaces navigator.credentials.create/get (publicKey
 * only) with calls to the bindings and builds PublicKeyCredential-shaped
 * objects from their answers. Self-contained: it is serialised into the page.
 */
function pageScript(names: { create: string; get: string }): void {
  const w = window as unknown as Record<string, (req: unknown) => Promise<Record<string, unknown>>>;
  const toBytes = (v: ArrayBuffer | ArrayBufferView): Uint8Array =>
    v instanceof ArrayBuffer ? new Uint8Array(v) : new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  const enc = (v: ArrayBuffer | ArrayBufferView): string => {
    let s = '';
    for (const c of toBytes(v)) s += String.fromCharCode(c);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const dec = (s: string): ArrayBuffer => {
    let t = s.replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4) t += '=';
    const bin = atob(t);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const check = (res: Record<string, unknown>) => {
    const err = res.error as { name: string; message: string } | undefined;
    if (err) throw new DOMException(err.message, err.name);
  };
  const credential = (res: Record<string, unknown>, response: Record<string, unknown>, json: Record<string, unknown>) => ({
    id: res.id,
    rawId: dec(res.id as string),
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response,
    getClientExtensionResults: () => ({}),
    toJSON: () => ({
      id: res.id,
      rawId: res.id,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: json,
      clientExtensionResults: {},
    }),
  });

  const container = navigator.credentials;
  const origCreate = container.create.bind(container);
  const origGet = container.get.bind(container);

  Object.defineProperty(container, 'create', {
    configurable: true,
    value: async (options?: CredentialCreationOptions) => {
      const pk = options?.publicKey;
      if (!pk) return origCreate(options);
      const res = await w[names.create]({
        origin: location.origin,
        rpId: pk.rp.id || location.hostname,
        challenge: enc(pk.challenge),
        userId: enc(pk.user.id),
        algs: (pk.pubKeyCredParams || []).map((p) => p.alg),
        excludeCredentials: (pk.excludeCredentials || []).map((c) => enc(c.id)),
      });
      check(res);
      const json = {
        clientDataJSON: res.clientDataJSON,
        attestationObject: res.attestationObject,
        authenticatorData: res.authenticatorData,
        publicKey: res.publicKey,
        publicKeyAlgorithm: -7,
        transports: ['internal'],
      };
      return credential(res, {
        clientDataJSON: dec(res.clientDataJSON as string),
        attestationObject: dec(res.attestationObject as string),
        getTransports: () => ['internal'],
        getAuthenticatorData: () => dec(res.authenticatorData as string),
        getPublicKey: () => dec(res.publicKey as string),
        getPublicKeyAlgorithm: () => -7,
      }, json);
    },
  });

  Object.defineProperty(container, 'get', {
    configurable: true,
    value: async (options?: CredentialRequestOptions) => {
      const pk = options?.publicKey;
      if (!pk) return origGet(options);
      if (options?.mediation === 'conditional') {
        // No autofill UI: a conditional request never settles on its own.
        return new Promise(() => undefined);
      }
      const res = await w[names.get]({
        origin: location.origin,
        rpId: pk.rpId || location.hostname,
        challenge: enc(pk.challenge),
        allowCredentials: (pk.allowCredentials || []).map((c) => enc(c.id)),
      });
      check(res);
      const json = {
        clientDataJSON: res.clientDataJSON,
        authenticatorData: res.authenticatorData,
        signature: res.signature,
        userHandle: res.userHandle,
      };
      return credential(res, {
        clientDataJSON: dec(res.clientDataJSON as string),
        authenticatorData: dec(res.authenticatorData as string),
        signature: dec(res.signature as string),
        userHandle: dec(res.userHandle as string),
      }, json);
    },
  });
}
