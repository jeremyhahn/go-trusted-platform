import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { deleteCookie, getCookie, setCookie } from "./cookie";

const NAMES = ["alpha", "beta", "xalpha", "a b", "a%20b"];

function wipe(): void {
  for (const name of NAMES) {
    document.cookie = `${name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/`;
  }
}

describe("getCookie", () => {
  beforeEach(wipe);
  afterEach(() => {
    vi.unstubAllGlobals();
    wipe();
  });

  it("returns null when the cookie is absent", () => {
    expect(getCookie("alpha")).toBeNull();
  });

  it("returns the value of the only cookie", () => {
    document.cookie = "alpha=1; path=/";
    expect(getCookie("alpha")).toBe("1");
  });

  it("returns the named cookie among others", () => {
    document.cookie = "beta=2; path=/";
    document.cookie = "alpha=1; path=/";
    expect(getCookie("alpha")).toBe("1");
    expect(getCookie("beta")).toBe("2");
  });

  it("does not match a cookie whose name only ends with the name", () => {
    document.cookie = "xalpha=9; path=/";
    expect(getCookie("alpha")).toBeNull();
  });

  it("returns an empty string for a cookie with an empty value", () => {
    document.cookie = "alpha=; path=/";
    expect(getCookie("alpha")).toBe("");
  });

  it("returns the stored value without decoding it", () => {
    document.cookie = "alpha=a%20b; path=/";
    expect(getCookie("alpha")).toBe("a%20b");
  });

  it("returns null when there is no document", () => {
    vi.stubGlobal("document", undefined);
    expect(getCookie("alpha")).toBeNull();
  });
});

describe("setCookie", () => {
  beforeEach(wipe);
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    wipe();
  });

  function captureWrite(fn: () => void): string[] {
    const writes: string[] = [];
    vi.spyOn(document, "cookie", "set").mockImplementation((v: string) => {
      writes.push(v);
    });
    fn();
    return writes;
  }

  it("sets a cookie getCookie can read back", () => {
    setCookie("alpha", "1");
    expect(getCookie("alpha")).toBe("1");
  });

  it("writes name and value with the default path", () => {
    expect(captureWrite(() => setCookie("alpha", "1"))).toEqual([
      "alpha=1; path=/",
    ]);
  });

  it("URI-encodes the name and the value", () => {
    expect(captureWrite(() => setCookie("a b", "x;y=z"))).toEqual([
      "a%20b=x%3By%3Dz; path=/",
    ]);
  });

  it("writes every option in order", () => {
    const expires = new Date(Date.UTC(2030, 0, 2, 3, 4, 5));
    const writes = captureWrite(() =>
      setCookie("alpha", "1", {
        expires,
        "max-age": 60,
        path: "/app",
        domain: "host-a",
        secure: true,
        sameSite: "Strict",
      }),
    );
    expect(writes).toEqual([
      `alpha=1; expires=${expires.toUTCString()}; max-age=60; path=/app; domain=host-a; secure; samesite=Strict`,
    ]);
  });

  it("writes a zero max-age", () => {
    expect(captureWrite(() => setCookie("alpha", "1", { "max-age": 0 }))).toEqual([
      "alpha=1; max-age=0; path=/",
    ]);
  });

  it("omits secure when it is false and an empty domain", () => {
    expect(
      captureWrite(() => setCookie("alpha", "1", { secure: false, domain: "" })),
    ).toEqual(["alpha=1; path=/"]);
  });

  it("does nothing when there is no document", () => {
    vi.stubGlobal("document", undefined);
    expect(() => setCookie("alpha", "1")).not.toThrow();
  });
});

describe("deleteCookie", () => {
  beforeEach(wipe);
  afterEach(() => {
    vi.restoreAllMocks();
    wipe();
  });

  it("removes a cookie", () => {
    setCookie("alpha", "1");
    deleteCookie("alpha");
    expect(getCookie("alpha")).toBeNull();
  });

  it("leaves other cookies in place", () => {
    setCookie("alpha", "1");
    setCookie("beta", "2");
    deleteCookie("alpha");
    expect(getCookie("beta")).toBe("2");
  });

  it("writes an empty value with a negative max-age", () => {
    const writes: string[] = [];
    vi.spyOn(document, "cookie", "set").mockImplementation((v: string) => {
      writes.push(v);
    });
    deleteCookie("alpha");
    expect(writes).toEqual(["alpha=; max-age=-1; path=/"]);
  });

  it("is a no-op for an absent cookie", () => {
    expect(() => deleteCookie("alpha")).not.toThrow();
    expect(getCookie("alpha")).toBeNull();
  });
});
