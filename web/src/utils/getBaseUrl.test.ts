import { afterEach, describe, expect, it, vi } from "vitest";

import { getBaseUrl } from "./getBaseUrl";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("getBaseUrl in the browser", () => {
  it("returns the origin of the current location", () => {
    // vitest.config sets the jsdom origin to https on localhost, no port.
    expect(getBaseUrl()).toBe("https://localhost");
  });

  it("includes a non-default port", () => {
    vi.stubGlobal("window", {
      location: { protocol: "http:", hostname: "host-a", port: "8080" },
    });
    expect(getBaseUrl()).toBe("http://host-a:8080");
  });

  it("omits an empty port", () => {
    vi.stubGlobal("window", {
      location: { protocol: "https:", hostname: "host-a", port: "" },
    });
    expect(getBaseUrl()).toBe("https://host-a");
  });
});

describe("getBaseUrl on the server", () => {
  function server(env: Record<string, string | undefined>): void {
    vi.stubGlobal("window", undefined);
    for (const name of ["VERCEL_URL", "HOSTNAME", "PORT"]) {
      vi.stubEnv(name, undefined);
    }
    vi.stubEnv("NODE_ENV", "test");
    for (const [name, value] of Object.entries(env)) {
      vi.stubEnv(name, value);
    }
  }

  it("defaults to http on localhost", () => {
    server({});
    expect(getBaseUrl()).toBe("http://localhost");
  });

  it("uses https in production", () => {
    server({ NODE_ENV: "production" });
    expect(getBaseUrl()).toBe("https://localhost");
  });

  it("uses HOSTNAME and PORT", () => {
    server({ HOSTNAME: "host-a", PORT: "3000" });
    expect(getBaseUrl()).toBe("http://host-a:3000");
  });

  it("uses https and the VERCEL_URL host when it is set", () => {
    server({ VERCEL_URL: "deploy-a", HOSTNAME: "host-a" });
    expect(getBaseUrl()).toBe("https://deploy-a");
  });

  it("omits an empty PORT", () => {
    server({ PORT: "" });
    expect(getBaseUrl()).toBe("http://localhost");
  });
});
