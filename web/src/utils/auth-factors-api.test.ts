import { ErrorCode } from "trusted-platform-sdk";
import { describe, expect, it } from "vitest";

import { toApiResponse } from "./auth-factors-api";

describe("toApiResponse", () => {
  it("carries the data of a successful result", () => {
    const data = { factors: [], total: 0 };

    expect(toApiResponse({ ok: true, data })).toEqual({ success: true, data });
  });

  it("maps an HTTP failure to the SDK code for its status", () => {
    const response = toApiResponse({ ok: false, error: "no such user", status: 404 });

    expect(response).toEqual({
      success: false,
      error: { code: ErrorCode.NOT_FOUND, message: "no such user", status: 404 },
    });
  });

  it("maps a transport failure to NETWORK_ERROR without a status", () => {
    const response = toApiResponse({ ok: false, error: "Failed to fetch", status: 0 });

    expect(response).toEqual({
      success: false,
      error: { code: ErrorCode.NETWORK_ERROR, message: "Failed to fetch" },
    });
  });
});
