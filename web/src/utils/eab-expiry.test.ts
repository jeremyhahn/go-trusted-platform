import { describe, expect, it } from "vitest";
import { parseExpiresIn } from "./eab-expiry";

describe("parseExpiresIn", () => {
  it("leaves the expiry unset for a blank input", () => {
    expect(parseExpiresIn("")).toEqual({ ok: true });
    expect(parseExpiresIn("   ")).toEqual({ ok: true });
  });

  it("accepts a positive whole number of seconds", () => {
    expect(parseExpiresIn("3600")).toEqual({ ok: true, seconds: 3600 });
  });

  it("refuses zero, negative, fractional, exponent and non-numeric input", () => {
    for (const input of ["0", "-1", "1.5", "1e3", "abc", " 12x"]) {
      expect(parseExpiresIn(input)).toEqual({ ok: false });
    }
  });

  it("refuses a value above Number.MAX_SAFE_INTEGER", () => {
    expect(parseExpiresIn("9007199254740993")).toEqual({ ok: false });
  });
});
