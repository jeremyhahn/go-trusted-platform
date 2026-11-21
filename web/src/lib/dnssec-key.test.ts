import { describe, expect, it } from "vitest";
import { describeDnssecKeys, dnskeySizeBits, dnssecAlgorithmName } from "./dnssec-key";

// #2165 Codex: the server fills only the DNSKEY records, so the UI derives the
// algorithm and key size from them.

function b64(bytes: number[]): string {
  return btoa(String.fromCharCode(...bytes));
}

const rsa2048 = b64([3, 1, 0, 1, 0xc5, ...Array(255).fill(0xab)]);

describe("dnssecAlgorithmName", () => {
  it("names the RFC 8624 algorithms", () => {
    expect(dnssecAlgorithmName(8)).toBe("RSASHA256");
    expect(dnssecAlgorithmName(10)).toBe("RSASHA512");
    expect(dnssecAlgorithmName(13)).toBe("ECDSAP256SHA256");
    expect(dnssecAlgorithmName(14)).toBe("ECDSAP384SHA384");
    expect(dnssecAlgorithmName(15)).toBe("ED25519");
    expect(dnssecAlgorithmName(16)).toBe("ED448");
    expect(dnssecAlgorithmName(200)).toBe("ALG200");
  });
});

describe("dnskeySizeBits", () => {
  it("sizes ECDSA and EdDSA keys from their length", () => {
    expect(dnskeySizeBits({ algorithm: 13, key: b64(Array(64).fill(1)) })).toBe(256);
    expect(dnskeySizeBits({ algorithm: 14, key: b64(Array(96).fill(1)) })).toBe(384);
    expect(dnskeySizeBits({ algorithm: 15, key: b64(Array(32).fill(1)) })).toBe(256);
    expect(dnskeySizeBits({ algorithm: 16, key: b64(Array(57).fill(1)) })).toBe(456);
    expect(dnskeySizeBits({ algorithm: 13, key: b64(Array(63).fill(1)) })).toBeUndefined();
  });

  it("sizes an RSA key from its modulus", () => {
    expect(dnskeySizeBits({ algorithm: 8, key: rsa2048 })).toBe(2048);
    expect(dnskeySizeBits({ algorithm: 8, key: b64([3, 1, 0, 1, 0x05, ...Array(255).fill(0xab)]) })).toBe(2043);
    expect(
      dnskeySizeBits({ algorithm: 10, key: b64([0, 0, 3, 1, 0, 1, 0xc5, ...Array(127).fill(0xab)]) })
    ).toBe(1024);
  });

  it("rejects keys it cannot read", () => {
    expect(dnskeySizeBits({ algorithm: 13, key: "not base64!" })).toBeUndefined();
    expect(dnskeySizeBits({ algorithm: 8, key: "" })).toBeUndefined();
  });
});

describe("describeDnssecKeys", () => {
  it("describes the zone keys, KSK first", () => {
    const ksk = { name: "example.com.", flags: 257, protocol: 3, algorithm: 13, key: b64(Array(64).fill(1)), ttl: 3600 };
    const zsk = { ...ksk, flags: 256 };
    expect(describeDnssecKeys([zsk, ksk])).toEqual({ algorithm: "ECDSAP256SHA256 (13)", keySize: "256" });
    expect(describeDnssecKeys([])).toEqual({ algorithm: undefined, keySize: undefined });
    expect(describeDnssecKeys(undefined)).toEqual({ algorithm: undefined, keySize: undefined });

    const rsaKsk = { ...ksk, algorithm: 8, key: rsa2048 };
    expect(describeDnssecKeys([zsk, rsaKsk])).toEqual({
      algorithm: "RSASHA256 (8), ECDSAP256SHA256 (13)",
      keySize: "2048",
    });
  });
});
