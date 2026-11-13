import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getCookie, setCookie } from "./cookie";
import { clearSession, revokeSession, storeSession } from "./session";
import type { Session } from "@/types/session";

// The cookies a session is made of. Every one of them must be gone after
// clearSession, which is the whole point of that function existing in one
// place (#212).
const SESSION_COOKIES = ["jwt", "refresh", "uid"];

function wipe(): void {
  for (const name of SESSION_COOKIES) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
}

const future = new Date(Date.now() + 3_600_000).toISOString();
const farFuture = new Date(Date.now() + 86_400_000).toISOString();

function session(overrides: Partial<Session> = {}): Session {
  return {
    bearer: "bearer.value",
    expiresAt: future,
    refreshToken: "refresh.value",
    refreshExpiresAt: farFuture,
    ...overrides,
  };
}

describe("storeSession", () => {
  beforeEach(wipe);
  afterEach(wipe);

  it("persists the bearer AND a renewal credential when one arrives", () => {
    // No renewal credential is issued while the platform mints the bearer,
    // but the pair returns together once the backbone's own bearer becomes
    // the session — and a refresh that arrived and was dropped here would
    // leave the client unable to renew.
    storeSession(session());

    expect(getCookie("jwt")).toBe("bearer.value");
    expect(getCookie("refresh")).toBe("refresh.value");
  });

  it("stores the bearer alone when the login issues no refresh", () => {
    storeSession(session({ refreshToken: undefined, refreshExpiresAt: undefined }));

    expect(getCookie("jwt")).toBe("bearer.value");
    expect(getCookie("refresh")).toBeNull();
  });

  it("drops a refresh credential left over from an earlier session", () => {
    // The previous principal's renewal credential must not survive a login
    // as somebody else. A refresh credential outlives its bearer and can
    // mint new ones, so storing a session replaces it whole.
    storeSession(session({ refreshToken: "previous.principal.refresh" }));
    expect(getCookie("refresh")).toBe("previous.principal.refresh");

    storeSession(session({ refreshToken: undefined, refreshExpiresAt: undefined }));

    expect(getCookie("jwt")).toBe("bearer.value");
    expect(getCookie("refresh")).toBeNull();
  });

  it("keeps a session whose credentials carry no expiry", () => {
    // A missing expiry means a session cookie rather than a dropped one: the
    // credential is still usable for this browser session.
    storeSession(session({ expiresAt: undefined, refreshExpiresAt: undefined }));

    expect(getCookie("jwt")).toBe("bearer.value");
    expect(getCookie("refresh")).toBe("refresh.value");
  });

  it("overwrites the previous session rather than layering on it", () => {
    storeSession(session());
    storeSession(session({ bearer: "second.bearer", refreshToken: "second.refresh" }));

    expect(getCookie("jwt")).toBe("second.bearer");
    expect(getCookie("refresh")).toBe("second.refresh");
  });
});

describe("clearSession", () => {
  beforeEach(wipe);
  afterEach(wipe);

  it("removes every cookie a session consists of", () => {
    storeSession(session());
    document.cookie = "uid=12345; path=/";

    clearSession();

    for (const name of SESSION_COOKIES) {
      expect(getCookie(name)).toBeNull();
    }
  });

  it("removes the renewal credential, not just the bearer", () => {
    // This is the case that matters most. A refresh credential surviving
    // logout is worse than a stale bearer: it mints fresh bearers long after
    // the one it was issued with expired, so a half-clear leaves the session
    // alive rather than merely looking alive (#212, #213).
    storeSession(session());
    expect(getCookie("refresh")).toBe("refresh.value");

    clearSession();

    expect(getCookie("refresh")).toBeNull();
  });

  it("is safe to call when no session was ever stored", () => {
    expect(() => clearSession()).not.toThrow();
    for (const name of SESSION_COOKIES) {
      expect(getCookie(name)).toBeNull();
    }
  });
});

// #215: signing out must revoke the bearer on the server, not only drop
// the browser's copy of it.
describe("revokeSession", () => {
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    wipe();
    fetchMock = vi.fn(() => Promise.resolve(new Response(null, { status: 200 })));
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    wipe();
  });

  it("posts the bearer to the logout endpoint", () => {
    setCookie("jwt", "the-bearer", { secure: true, sameSite: "Strict" });

    revokeSession();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toMatch(/\/api\/v1\/logout$/);
    expect(init.method).toBe("POST");
    expect(init.keepalive).toBe(true);
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer the-bearer",
    );
  });

  it("sends the bearer it read even when the cookies are cleared right after", () => {
    setCookie("jwt", "the-bearer", { secure: true, sameSite: "Strict" });

    revokeSession();
    clearSession();

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBe(
      "Bearer the-bearer",
    );
  });

  it("does nothing when there is no session", () => {
    revokeSession();

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("swallows a failed request", async () => {
    setCookie("jwt", "the-bearer", { secure: true, sameSite: "Strict" });
    fetchMock.mockImplementation(() => Promise.reject(new Error("offline")));

    expect(() => revokeSession()).not.toThrow();
    await Promise.resolve();
  });
});
