// @vitest-environment node
import { createPrivateKey, createPublicKey, verify } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

import { buildCSR, CSRBuildError, generateMTLSCredential } from "./csr";

interface TLV {
  tag: number;
  // The whole element, header included.
  raw: Uint8Array;
  content: Uint8Array;
}

// readTLV decodes the DER element at offset (definite lengths only).
function readTLV(buf: Uint8Array, offset = 0): TLV {
  const tag = buf[offset];
  let length = buf[offset + 1];
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + buf[offset + 2 + i];
    }
    header += count;
  }
  return {
    tag,
    raw: buf.subarray(offset, offset + header + length),
    content: buf.subarray(offset + header, offset + header + length),
  };
}

function children(parent: TLV): TLV[] {
  const out: TLV[] = [];
  for (let offset = 0; offset < parent.content.length; ) {
    const child = readTLV(parent.content, offset);
    out.push(child);
    offset += child.raw.length;
  }
  return out;
}

function pemBody(pem: string, label: string): Uint8Array {
  const lines = pem.trim().split("\n");
  expect(lines[0]).toBe(`-----BEGIN ${label}-----`);
  expect(lines[lines.length - 1]).toBe(`-----END ${label}-----`);
  for (const line of lines.slice(1, -1)) {
    expect(line.length).toBeLessThanOrEqual(64);
  }
  return Uint8Array.from(Buffer.from(lines.slice(1, -1).join(""), "base64"));
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

interface ParsedCSR {
  requestInfo: TLV;
  version: TLV;
  subject: TLV;
  spki: TLV;
  attributes: TLV;
  signatureAlgorithm: TLV;
  signature: TLV;
}

function parseCSR(pem: string): ParsedCSR {
  const request = readTLV(pemBody(pem, "CERTIFICATE REQUEST"));
  expect(request.tag).toBe(0x30);
  const [requestInfo, signatureAlgorithm, signature] = children(request);
  const [version, subject, spki, attributes] = children(requestInfo);
  return { requestInfo, version, subject, spki, attributes, signatureAlgorithm, signature };
}

// expectedSubject is Name = SEQUENCE { SET { SEQUENCE { id-at-commonName,
// UTF8String cn } } } for a short CN.
function expectedSubject(cn: string): string {
  const value = Buffer.from(cn, "utf8");
  const atv = Buffer.concat([
    Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, value.length]),
    value,
  ]);
  const set = Buffer.concat([Buffer.from([0x31, atv.length + 2, 0x30, atv.length]), atv]);
  return hex(Buffer.concat([Buffer.from([0x30, set.length]), set]));
}

function p256KeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("buildCSR", () => {
  it("encodes a signed PKCS#10 request whose subject is exactly CN=<user id>", async () => {
    const keyPair = await p256KeyPair();
    const csr = parseCSR(await buildCSR(keyPair, "alice"));

    expect(hex(csr.version.raw)).toBe("020100");
    expect(hex(csr.subject.raw)).toBe(expectedSubject("alice"));
    // An empty [0] attributes set: no extension request, so no SANs.
    expect(hex(csr.attributes.raw)).toBe("a000");
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", keyPair.publicKey));
    expect(hex(csr.spki.raw)).toBe(hex(spki));
    // SEQUENCE { ecdsa-with-SHA256 } with absent parameters (RFC 5758 §3.2).
    expect(hex(csr.signatureAlgorithm.raw)).toBe("300a06082a8648ce3d040302");

    // BIT STRING with zero unused bits around a DER Ecdsa-Sig-Value, which
    // node verifies against the request info with the CSR's own public key.
    expect(csr.signature.tag).toBe(0x03);
    expect(csr.signature.content[0]).toBe(0);
    const publicKey = createPublicKey({ key: Buffer.from(csr.spki.raw), format: "der", type: "spki" });
    const derSignature = csr.signature.content.subarray(1);
    expect(verify("sha256", csr.requestInfo.raw, publicKey, derSignature)).toBe(true);
  });

  it("uses long-form DER lengths for a subject over 127 bytes", async () => {
    const cn = "u".repeat(200);
    const keyPair = await p256KeyPair();
    const csr = parseCSR(await buildCSR(keyPair, cn));

    const [set] = children(csr.subject);
    const [atv] = children(set);
    const [, value] = children(atv);
    expect(value.tag).toBe(0x0c);
    expect(Buffer.from(value.content).toString("utf8")).toBe(cn);
    const publicKey = createPublicKey({ key: Buffer.from(csr.spki.raw), format: "der", type: "spki" });
    expect(verify("sha256", csr.requestInfo.raw, publicKey, csr.signature.content.subarray(1))).toBe(true);
  });

  it("encodes r and s as minimal positive DER integers", async () => {
    // r has its high bit set (needs a 0x00 pad); s has leading zero bytes
    // (must be trimmed).
    const r = new Uint8Array(32).fill(0x80);
    const s = new Uint8Array(32);
    s[30] = 0x01;
    s[31] = 0x02;
    vi.spyOn(crypto.subtle, "sign").mockResolvedValue(Uint8Array.from([...r, ...s]).buffer);

    const csr = parseCSR(await buildCSR(await p256KeyPair(), "alice"));
    const ecdsaSig = readTLV(csr.signature.content.subarray(1));
    const [derR, derS] = children(ecdsaSig);
    expect(hex(derR.raw)).toBe("0221" + "00" + "80".repeat(32));
    expect(hex(derS.raw)).toBe("02020102");
  });

  it("rejects an empty common name", async () => {
    await expect(buildCSR(await p256KeyPair(), "")).rejects.toThrow(CSRBuildError);
  });

  it("rejects a key pair that is not ECDSA P-256", async () => {
    const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, [
      "sign",
      "verify",
    ]);
    await expect(buildCSR(p384, "alice")).rejects.toThrow(CSRBuildError);
  });

  it("rejects a signature that is not 64 bytes of r || s", async () => {
    vi.spyOn(crypto.subtle, "sign").mockResolvedValue(new Uint8Array(70).buffer);
    await expect(buildCSR(await p256KeyPair(), "alice")).rejects.toThrow(CSRBuildError);
  });
});

describe("generateMTLSCredential", () => {
  it("returns a CSR and the PKCS#8 private key that signed it", async () => {
    const { csrPEM, privateKeyPEM } = await generateMTLSCredential("bob");

    const csr = parseCSR(csrPEM);
    expect(hex(csr.subject.raw)).toBe(expectedSubject("bob"));
    const privateKey = createPrivateKey({
      key: Buffer.from(pemBody(privateKeyPEM, "PRIVATE KEY")),
      format: "der",
      type: "pkcs8",
    });
    const derivedSPKI = createPublicKey(privateKey).export({ format: "der", type: "spki" });
    expect(hex(derivedSPKI)).toBe(hex(csr.spki.raw));
  });

  it("propagates the CSR error for an empty common name", async () => {
    await expect(generateMTLSCredential("")).rejects.toThrow(CSRBuildError);
  });
});
