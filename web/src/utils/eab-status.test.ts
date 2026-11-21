import { describe, expect, it } from "vitest";
import { normalizeEABStatus } from "./eab-status";

describe("normalizeEABStatus", () => {
  it("strips the protobuf enum prefix the REST handlers send", () => {
    expect(normalizeEABStatus("EAB_CREDENTIAL_STATUS_ACTIVE")).toBe("ACTIVE");
    expect(normalizeEABStatus("EAB_CREDENTIAL_STATUS_REVOKED")).toBe("REVOKED");
    expect(normalizeEABStatus("EAB_CREDENTIAL_STATUS_EXPIRED")).toBe("EXPIRED");
    expect(normalizeEABStatus("EAB_CREDENTIAL_STATUS_USED")).toBe("USED");
  });

  it("keeps a short status name unchanged", () => {
    expect(normalizeEABStatus("ACTIVE")).toBe("ACTIVE");
    expect(normalizeEABStatus("USED")).toBe("USED");
  });

  it("maps the unspecified enum value to UNSPECIFIED", () => {
    expect(normalizeEABStatus("EAB_CREDENTIAL_STATUS_UNSPECIFIED")).toBe("UNSPECIFIED");
  });

  it("returns an empty string for undefined", () => {
    expect(normalizeEABStatus(undefined)).toBe("");
  });
});
