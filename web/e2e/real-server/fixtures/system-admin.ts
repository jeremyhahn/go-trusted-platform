import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import type { APIRequestContext } from '@playwright/test';
import type { SoftAuthenticator } from './soft-authenticator';

/**
 * The system-tenant admin of a real-server run, signed in through the admin
 * claim ceremony (docs/auth/api.md, pkg/webservice/v1/adminclaim): prove
 * possession of the node's admin bundle, enrol a passkey from the software
 * authenticator, and take the console bearer the ceremony returns.
 *
 * The claim runs once per node: a second one is refused while an
 * authenticator is enrolled. The bearer is therefore persisted (mode 0600)
 * in the run directory, and every later worker or test reuses it.
 */

/** The admin claim bundle platformd writes under its quicbaas data dir. */
export function adminBundlePaths(runDir: string): { cert: string; key: string } {
  const dir = path.join(runDir, 'trusted-data', 'quicbaas', 'admin');
  return { cert: path.join(dir, 'admin.crt'), key: path.join(dir, 'admin.key') };
}

/** Where the system admin's session bearer is persisted for the run. */
export function systemSessionFile(runDir: string): string {
  return path.join(runDir, 'system-admin-session.json');
}

/**
 * Signs the claim challenge with the bundle key, as the server's
 * ProveRequest verifies it: over the challenge string as sent, SHA-256 for
 * ECDSA (ASN.1 DER) and RSA (PKCS#1 v1.5), unhashed for Ed25519. Returns
 * standard base64 (the JSON form of a Go []byte).
 */
export function signClaimChallenge(keyPem: string, challenge: string): string {
  const key = crypto.createPrivateKey(keyPem);
  const alg = key.asymmetricKeyType === 'ed25519' ? null : 'sha256';
  return crypto.sign(alg, Buffer.from(challenge, 'utf8'), key).toString('base64');
}

/** The body of POST /api/v1/admin/claim/verify. */
export function proveBody(
  challenge: string,
  certPem: string,
  keyPem: string,
): { challenge: string; certificate_pem: string; signature: string } {
  return { challenge, certificate_pem: certPem, signature: signClaimChallenge(keyPem, challenge) };
}

type Json = Record<string, unknown>;

/** The answer of one claim step: the payload of an envelope, or the body itself. */
async function claimStep(
  request: APIRequestContext,
  step: string,
  url: string,
  opts: { headers?: Record<string, string>; data?: unknown } = {},
): Promise<Json> {
  const res = await request.post(url, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    data: opts.data === undefined ? undefined : JSON.stringify(opts.data),
    failOnStatusCode: false,
    maxRedirects: 0,
  });
  const text = await res.text();
  if (res.status() < 200 || res.status() >= 300) {
    throw new Error(`[real-server] admin claim ${step}: ${res.status()} ${text}`);
  }
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`[real-server] admin claim ${step}: ${res.status()} ${text}`);
  }
  if (body && typeof body === 'object' && 'success' in body && 'payload' in body) {
    body = (body as Json).payload;
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error(`[real-server] admin claim ${step}: ${res.status()} ${text}`);
  }
  return body as Json;
}

function str(v: unknown, what: string): string {
  if (typeof v !== 'string' || !v) throw new Error(`[real-server] admin claim: no ${what} in the answer`);
  return v;
}

/**
 * The system admin's console bearer: the persisted one when this run already
 * claimed the node, otherwise a fresh claim (challenge, verify, passkey
 * begin and finish), persisted before it is returned.
 */
export async function claimSystemAdmin(
  request: APIRequestContext,
  runDir: string,
  authenticator: SoftAuthenticator,
  origin: string,
): Promise<string> {
  const sessionFile = systemSessionFile(runDir);
  if (fs.existsSync(sessionFile)) {
    return str((JSON.parse(fs.readFileSync(sessionFile, 'utf8')) as Json).token, 'persisted token');
  }

  const bundle = adminBundlePaths(runDir);
  const certPem = fs.readFileSync(bundle.cert, 'utf8');
  const keyPem = fs.readFileSync(bundle.key, 'utf8');

  const challenge = str((await claimStep(request, 'challenge', '/api/v1/admin/claim/challenge')).challenge, 'challenge');
  const verified = await claimStep(request, 'verify', '/api/v1/admin/claim/verify', {
    data: proveBody(challenge, certPem, keyPem),
  });
  const claimToken = str(verified.claim_token, 'claim_token');

  const creation = await claimStep(request, 'passkey begin', '/api/v1/admin/claim/passkey/begin', {
    headers: { 'X-Admin-Claim': claimToken },
  });
  const sessionId = str(creation.session_id, 'session_id');
  const pk = (creation.publicKey ?? creation) as {
    challenge?: string;
    rp?: { id?: string };
    user?: { id?: string };
    pubKeyCredParams?: Array<{ alg: number }>;
    excludeCredentials?: Array<{ id: string }>;
  };
  const made = authenticator.makeCredential({
    origin,
    rpId: pk.rp?.id || new URL(origin).hostname,
    challenge: str(pk.challenge, 'publicKey.challenge'),
    userId: str(pk.user?.id, 'publicKey.user.id'),
    algs: (pk.pubKeyCredParams ?? []).map((p) => p.alg),
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => c.id),
  });
  if ('error' in made) {
    throw new Error(`[real-server] admin claim passkey create: ${made.error.name} ${made.error.message}`);
  }
  // The navigator.credentials.create() JSON, as the page script builds it.
  const created = {
    id: made.id,
    rawId: made.id,
    type: 'public-key',
    authenticatorAttachment: 'platform',
    response: {
      clientDataJSON: made.clientDataJSON,
      attestationObject: made.attestationObject,
      authenticatorData: made.authenticatorData,
      publicKey: made.publicKey,
      publicKeyAlgorithm: -7,
      transports: ['internal'],
    },
    clientExtensionResults: {},
  };
  const finished = await claimStep(request, 'passkey finish', '/api/v1/admin/claim/passkey/finish', {
    headers: { 'X-Admin-Claim': claimToken, 'X-Session-Id': sessionId },
    data: created,
  });
  if (finished.tenant_id !== 'system') {
    throw new Error(`[real-server] admin claim passkey finish: tenant_id ${String(finished.tenant_id)}, want system`);
  }
  const token = str(finished.token, 'token');
  fs.writeFileSync(sessionFile, JSON.stringify({ token }), { mode: 0o600 });
  return token;
}
