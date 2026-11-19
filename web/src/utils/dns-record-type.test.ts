import { describe, expect, it } from "vitest";

import {
  UnsupportedRecordTypeError,
  isRecordType,
  toRecordType,
} from "./dns-record-type";

const SUPPORTED = [
  "UNSPECIFIED", "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "SOA", "CAA",
  "TLSA", "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
];

const UNSUPPORTED = ["", "a", "aaaa", "PTR", " A", "A ", "NSEC4", "unknown"];

describe("isRecordType", () => {
  it.each(SUPPORTED)("accepts %s", (value) => {
    expect(isRecordType(value)).toBe(true);
  });

  it.each(UNSUPPORTED)("rejects %j", (value) => {
    expect(isRecordType(value)).toBe(false);
  });
});

describe("toRecordType", () => {
  it.each(SUPPORTED)("returns %s unchanged", (value) => {
    expect(toRecordType(value)).toBe(value);
  });

  it.each(UNSUPPORTED)("throws UnsupportedRecordTypeError for %j", (value) => {
    expect(() => toRecordType(value)).toThrow(UnsupportedRecordTypeError);
  });

  it("carries the rejected value on the error", () => {
    try {
      toRecordType("PTR");
      expect.unreachable("toRecordType did not throw");
    } catch (err) {
      expect(err).toBeInstanceOf(UnsupportedRecordTypeError);
      expect((err as UnsupportedRecordTypeError).recordType).toBe("PTR");
    }
  });
});

describe("UnsupportedRecordTypeError", () => {
  it("is an Error with its own name, message and record type", () => {
    const err = new UnsupportedRecordTypeError("PTR");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("UnsupportedRecordTypeError");
    expect(err.message).toBe("record type PTR is not in the DNS SDK contract");
    expect(err.recordType).toBe("PTR");
  });

  it("keeps an empty record type", () => {
    const err = new UnsupportedRecordTypeError("");
    expect(err.recordType).toBe("");
    expect(err.message).toBe("record type  is not in the DNS SDK contract");
  });
});
