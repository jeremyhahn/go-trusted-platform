import { describe, expect, it } from "vitest";
import { base64ToPem, pemToBase64 } from "./pem-base64";

const MULTI_LINE_PEM =
  "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUQ2E=\nZm9vYmFy\n-----END CERTIFICATE-----\n";

describe("pemToBase64 / base64ToPem", () => {
  it("round-trips a multi-line PEM", () => {
    const encoded = pemToBase64(MULTI_LINE_PEM);
    expect(encoded.startsWith("-----BEGIN")).toBe(false);
    expect(base64ToPem(encoded)).toBe(MULTI_LINE_PEM);
  });

  it("encodes a short PEM to its known standard base64", () => {
    const pem = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----";
    const expected =
      "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkNFUlQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==";
    expect(pemToBase64(pem)).toBe(expected);
    expect(base64ToPem(expected)).toBe(pem);
  });

  it("passes plain PEM through base64ToPem unchanged", () => {
    expect(base64ToPem(MULTI_LINE_PEM)).toBe(MULTI_LINE_PEM);
  });

  it("passes invalid base64 through base64ToPem unchanged", () => {
    expect(base64ToPem("not base64 !!")).toBe("not base64 !!");
  });
});
