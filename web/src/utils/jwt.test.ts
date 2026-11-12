import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { decodeJWT, getTokenFromCookie, getUserFromToken } from "./jwt";
import type { JWTPayload } from "./jwt";

function b64url(text: string): string {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function token(payload: unknown): string {
  return `${b64url('{"alg":"none"}')}.${b64url(JSON.stringify(payload))}.sig`;
}

function wipe(): void {
  document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
}

describe("decodeJWT", () => {
  it("decodes every payload field", () => {
    const payload: JWTPayload = {
      sub: "user-1",
      user_id: "uid-1",
      email: "a@example.test",
      tenant_id: "t-1",
      is_tenant_owner: true,
      roles: ["admin", "viewer"],
      exp: 1_900_000_000,
      iat: 1_800_000_000,
    };
    expect(decodeJWT(token(payload))).toEqual(payload);
  });

  it("decodes base64url payloads that carry - and _ characters", () => {
    // "??>" encodes to "Pz8-" in base64url and "?~" to "P34"; both need the
    // url-safe alphabet mapped back before atob.
    const payload = { sub: "??>??>", email: "?~?~?" };
    const encoded = b64url(JSON.stringify(payload));
    expect(encoded).toMatch(/[-_]/);
    expect(decodeJWT(token(payload))).toEqual(payload);
  });

  it.each([
    ["no padding", { sub: "a" }],
    ["one pad char", { sub: "ab" }],
    ["two pad chars", { sub: "abc" }],
  ])("restores the stripped padding (%s)", (_name, payload) => {
    expect(decodeJWT(token(payload))).toEqual(payload);
  });

  it.each([
    ["empty string", ""],
    ["one part", "abc"],
    ["two parts", "abc.def"],
    ["four parts", "a.b.c.d"],
  ])("returns null for a token with the wrong part count (%s)", (_name, t) => {
    expect(decodeJWT(t)).toBeNull();
  });

  it("returns null when the payload is not base64", () => {
    expect(decodeJWT("a.!!!!.c")).toBeNull();
  });

  it("returns null when the payload is not JSON", () => {
    expect(decodeJWT(`a.${b64url("not json")}.c`)).toBeNull();
  });

  it("returns null when the payload part is empty", () => {
    expect(decodeJWT("a..c")).toBeNull();
  });
});

describe("getTokenFromCookie", () => {
  beforeEach(wipe);
  afterEach(wipe);

  it("returns null when no jwt cookie is set", () => {
    expect(getTokenFromCookie()).toBeNull();
  });

  it("returns the jwt cookie value", () => {
    document.cookie = "jwt=abc.def.ghi; path=/";
    expect(getTokenFromCookie()).toBe("abc.def.ghi");
  });
});

describe("getUserFromToken", () => {
  beforeEach(wipe);
  afterEach(wipe);

  function setToken(payload: unknown): void {
    document.cookie = `jwt=${token(payload)}; path=/`;
  }

  it("returns null when there is no token", () => {
    expect(getUserFromToken()).toBeNull();
  });

  it("returns null when the token does not decode", () => {
    document.cookie = "jwt=garbage; path=/";
    expect(getUserFromToken()).toBeNull();
  });

  it("maps a full payload to a user", () => {
    setToken({
      sub: "user-1",
      email: "a@example.test",
      tenant_id: "t-1",
      is_tenant_owner: true,
      roles: ["admin"],
    });
    expect(getUserFromToken()).toEqual({
      id: "user-1",
      email: "a@example.test",
      tenantId: "t-1",
      isTenantOwner: true,
      roles: ["admin"],
    });
  });

  it("prefers sub over user_id", () => {
    setToken({ sub: "from-sub", user_id: "from-uid", email: "a@example.test" });
    expect(getUserFromToken()?.id).toBe("from-sub");
  });

  it("falls back to user_id when sub is missing", () => {
    setToken({ user_id: "from-uid", email: "a@example.test" });
    expect(getUserFromToken()?.id).toBe("from-uid");
  });

  it("defaults tenantId, isTenantOwner and roles", () => {
    setToken({ sub: "u", email: "a@example.test" });
    expect(getUserFromToken()).toEqual({
      id: "u",
      email: "a@example.test",
      tenantId: null,
      isTenantOwner: false,
      roles: [],
    });
  });

  it("returns null without a user id", () => {
    setToken({ email: "a@example.test" });
    expect(getUserFromToken()).toBeNull();
  });

  it("returns null with an empty user id", () => {
    setToken({ sub: "", user_id: "", email: "a@example.test" });
    expect(getUserFromToken()).toBeNull();
  });

  it("returns null without an email", () => {
    setToken({ sub: "u" });
    expect(getUserFromToken()).toBeNull();
  });
});
