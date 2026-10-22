/**
 * Browser-side PKCS#10 certificate signing requests (RFC 2986) for the mTLS
 * auth factor.
 *
 * The key pair is an ECDSA P-256 WebCrypto key generated in the browser; the
 * private key never leaves it except as the PKCS#8 PEM handed back to the
 * user. The CSR carries only what the platform's issue-cert handler accepts:
 * a subject of exactly CN=<user id>, no OU and no subjectAltName (see
 * csrBoundToUser in pkg/api/rest/auth_factor_handlers.go).
 */

/** Raised when a CSR cannot be built from the given inputs. */
export class CSRBuildError extends Error {
  constructor(reason: string) {
    super(`cannot build CSR: ${reason}`);
    this.name = "CSRBuildError";
  }
}

/** The PEM-encoded CSR and the PKCS#8 private key it was signed with. */
export interface MTLSCredential {
  csrPEM: string;
  privateKeyPEM: string;
}

// DER tags (X.690 §8).
const TAG_INTEGER = 0x02;
const TAG_BIT_STRING = 0x03;
const TAG_UTF8_STRING = 0x0c;
const TAG_SEQUENCE = 0x30;
const TAG_SET = 0x31;
const TAG_CONTEXT_0 = 0xa0;

// id-at-commonName, 2.5.4.3 (RFC 5280 Appendix A.1).
const OID_COMMON_NAME = Uint8Array.of(0x06, 0x03, 0x55, 0x04, 0x03);
// ecdsa-with-SHA256, 1.2.840.10045.4.3.2 (RFC 5758 §3.2).
const OID_ECDSA_WITH_SHA256 = Uint8Array.of(
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02
);

const P256_COORDINATE_BYTES = 32;

function concat(parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function derLength(length: number): Uint8Array {
  if (length < 0x80) {
    return Uint8Array.of(length);
  }
  const bytes: number[] = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) {
    bytes.unshift(n % 256);
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function der(tag: number, ...contents: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const body = concat(contents);
  return concat([Uint8Array.of(tag), derLength(body.length), body]);
}

// derUnsignedInteger encodes a big-endian unsigned magnitude as a minimal
// DER INTEGER: leading zeros dropped, one zero added back when the high bit
// would otherwise make it negative.
function derUnsignedInteger(magnitude: Uint8Array): Uint8Array {
  let start = 0;
  while (start < magnitude.length - 1 && magnitude[start] === 0) {
    start++;
  }
  const trimmed = magnitude.subarray(start);
  const body = trimmed[0] & 0x80 ? concat([Uint8Array.of(0), trimmed]) : trimmed;
  return der(TAG_INTEGER, body);
}

// WebCrypto returns an ECDSA signature as r || s (IEEE P1363); X.509 wants
// Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (RFC 3279 §2.2.3).
function p1363ToDER(signature: Uint8Array): Uint8Array {
  if (signature.length !== 2 * P256_COORDINATE_BYTES) {
    throw new CSRBuildError(`unexpected P-256 signature length ${signature.length}`);
  }
  const r = signature.subarray(0, P256_COORDINATE_BYTES);
  const s = signature.subarray(P256_COORDINATE_BYTES);
  return der(TAG_SEQUENCE, derUnsignedInteger(r), derUnsignedInteger(s));
}

function toPEM(label: string, bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  const lines = btoa(binary).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

/**
 * Builds a PEM "CERTIFICATE REQUEST" for subject CN=commonName, signed with
 * ECDSA-SHA256 by the key pair's private key. The key pair must be ECDSA
 * P-256.
 */
export async function buildCSR(keyPair: CryptoKeyPair, commonName: string): Promise<string> {
  if (commonName === "") {
    throw new CSRBuildError("common name is empty");
  }
  const algorithm = keyPair.privateKey.algorithm as EcKeyAlgorithm;
  if (algorithm.name !== "ECDSA" || algorithm.namedCurve !== "P-256") {
    throw new CSRBuildError("key pair is not ECDSA P-256");
  }

  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
  const subject = der(
    TAG_SEQUENCE,
    der(
      TAG_SET,
      der(TAG_SEQUENCE, OID_COMMON_NAME, der(TAG_UTF8_STRING, new TextEncoder().encode(commonName)))
    )
  );
  // CertificationRequestInfo (RFC 2986 §4.1): version 0, subject, SPKI and
  // an empty attributes set.
  const requestInfo = der(
    TAG_SEQUENCE,
    derUnsignedInteger(Uint8Array.of(0)),
    subject,
    spki,
    der(TAG_CONTEXT_0)
  );

  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, requestInfo)
  );
  const request = der(
    TAG_SEQUENCE,
    requestInfo,
    der(TAG_SEQUENCE, OID_ECDSA_WITH_SHA256),
    der(TAG_BIT_STRING, Uint8Array.of(0), p1363ToDER(signature))
  );
  return toPEM("CERTIFICATE REQUEST", request);
}

/**
 * Generates an ECDSA P-256 key pair and a CSR for subject CN=commonName.
 * The private key is returned as PKCS#8 PEM so the user can keep it with the
 * certificate the CA issues.
 */
export async function generateMTLSCredential(commonName: string): Promise<MTLSCredential> {
  const keyPair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, [
    "sign",
    "verify",
  ]);
  const csrPEM = await buildCSR(keyPair, commonName);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));
  return { csrPEM, privateKeyPEM: toPEM("PRIVATE KEY", pkcs8) };
}
