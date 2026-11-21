// The server's GetDNSSECStatus fills only the DNSKEY (and DS) records, leaving
// algorithm and keySize empty, so the UI derives both from the DNSKEY records
// (#2165 Codex).
import type { DNSKEYRecord } from "trusted-platform-sdk";

// RFC 8624 section 3.1 algorithm numbers and mnemonics.
const ALGORITHM_NAMES: Record<number, string> = {
  1: "RSAMD5",
  3: "DSA",
  5: "RSASHA1",
  6: "DSA-NSEC3-SHA1",
  7: "RSASHA1-NSEC3-SHA1",
  8: "RSASHA256",
  10: "RSASHA512",
  12: "ECC-GOST",
  13: "ECDSAP256SHA256",
  14: "ECDSAP384SHA384",
  15: "ED25519",
  16: "ED448",
};

// Algorithms whose public key has a fixed length (RFC 6605, RFC 8080).
const FIXED_KEY_BYTES: Record<number, [bytes: number, bits: number]> = {
  13: [64, 256],
  14: [96, 384],
  15: [32, 256],
  16: [57, 456],
};

// RSA algorithms whose key field follows RFC 3110.
const RSA_ALGORITHMS = new Set([1, 5, 7, 8, 10]);

export function dnssecAlgorithmName(n: number): string {
  return ALGORITHM_NAMES[n] ?? `ALG${n}`;
}

function decodeBase64(s: string): Uint8Array | undefined {
  if (!s) {
    return undefined;
  }
  try {
    const raw = atob(s);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
      bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
  } catch {
    return undefined;
  }
}

/** The key size in bits of one DNSKEY record, or undefined when it cannot be read. */
export function dnskeySizeBits(key: Pick<DNSKEYRecord, "algorithm" | "key">): number | undefined {
  const bytes = decodeBase64(key.key);
  if (!bytes) {
    return undefined;
  }
  const fixed = FIXED_KEY_BYTES[key.algorithm];
  if (fixed) {
    return bytes.length === fixed[0] ? fixed[1] : undefined;
  }
  if (!RSA_ALGORITHMS.has(key.algorithm) || bytes.length < 1) {
    return undefined;
  }
  // RFC 3110: one exponent-length byte, or a zero byte and a two-byte length.
  let expLen = bytes[0];
  let offset = 1;
  if (expLen === 0) {
    if (bytes.length < 3) {
      return undefined;
    }
    expLen = (bytes[1] << 8) | bytes[2];
    offset = 3;
  }
  let modulus = bytes.subarray(offset + expLen);
  let start = 0;
  while (start < modulus.length && modulus[start] === 0) {
    start++;
  }
  modulus = modulus.subarray(start);
  if (modulus.length === 0) {
    return undefined;
  }
  return modulus.length * 8 - (Math.clz32(modulus[0]) - 24);
}

/**
 * The zone's algorithms (KSK first, each as "MNEMONIC (n)") and the size of
 * the first key that can be sized.
 */
export function describeDnssecKeys(keys: DNSKEYRecord[] | undefined): { algorithm?: string; keySize?: string } {
  if (!keys || keys.length === 0) {
    return { algorithm: undefined, keySize: undefined };
  }
  const ordered = [...keys.filter((k) => (k.flags & 1) === 1), ...keys.filter((k) => (k.flags & 1) !== 1)];
  const algorithms: number[] = [];
  for (const k of ordered) {
    if (!algorithms.includes(k.algorithm)) {
      algorithms.push(k.algorithm);
    }
  }
  let keySize: string | undefined;
  for (const k of ordered) {
    const bits = dnskeySizeBits(k);
    if (bits !== undefined) {
      keySize = String(bits);
      break;
    }
  }
  return {
    algorithm: algorithms.map((n) => `${dnssecAlgorithmName(n)} (${n})`).join(", "),
    keySize,
  };
}
