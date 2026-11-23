import React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformProvider } from "trusted-platform-sdk";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";
import { TokenVerifyCard } from "./token-verify-card";

// #2053: Gated reads the server's capabilities through this hook; the card's own requests stay on the control-plane stub.
const caps = vi.hoisted(() => ({ capability: vi.fn() }));
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: caps.capability }),
}));

/**
 * TokenVerifyCard sends the pasted token through the SDK's iam.verifyToken
 * and shows the server's verdict only for the token that was verified,
 * never while a new call runs or after it fails. It runs on the real SDK
 * hooks and client over the control-plane fetch stub.
 */

const route = "POST /api/v1/iam/tokens/verify";
const verifyOp = "POST /api/v1/iam/tokens/verify";

function paste(token: string) {
  fireEvent.change(screen.getByLabelText("Token"), { target: { value: token } });
}

async function verify() {
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /Verify/ }));
  });
}

/** Mounts on an SDK client that does not retry, so failures settle at once. */
function withNoRetry(children: React.ReactNode) {
  return (
    <PlatformProvider
      config={{
        baseUrl: "https://control-plane.test/api",
        retry: { maxRetries: 0, retryOnNetworkError: false },
      }}
    >
      <>{children}</>
    </PlatformProvider>
  );
}

/**
 * The SDK client keeps the fetch it was built with, so a test that changes
 * the answer mid-test installs one delegating fetch.
 */
let current: typeof fetch;
function serve(setup: () => unknown) {
  setup();
  current = globalThis.fetch;
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => current(input, init));
}

/**
 * The control-plane stub records the path only; this wraps the installed
 * fetch to record each request's path and query, which carries tenant_id
 * (#2021 Codex round 5: the daemon's own-tenant guard reads it).
 */
function recordTargets(): string[] {
  const targets: string[] = [];
  const inner = globalThis.fetch;
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    targets.push(`${(init?.method ?? "GET").toUpperCase()} ${url.pathname}${url.search}`);
    return inner(input, init);
  });
  return targets;
}

describe("TokenVerifyCard", () => {
  beforeEach(() => {
    caps.capability.mockReset();
    caps.capability.mockImplementation(() => ({ enabled: true }));
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("sends the pasted token and shows a valid verdict", async () => {
    const sent = stubControlPlane({
      [route]: ok({
        valid: true,
        subject: "u-1",
        tenant_id: "t-1",
        scopes: ["iam:read"],
        roles: ["admin"],
        expires_at: "2026-12-01T00:00:00Z",
      }),
    });
    const targets = recordTargets();
    render(withControlPlane(<TokenVerifyCard tenantId="tenant-a" />));

    paste("abc.def.ghi");
    await verify();

    expect(await screen.findByText("Valid")).toBeDefined();
    expect(targets).toEqual(["POST /api/v1/iam/tokens/verify?tenant_id=tenant-a"]);
    expect(screen.getByText("u-1")).toBeDefined();
    expect(screen.getByText("t-1")).toBeDefined();
    expect(screen.getByText("iam:read")).toBeDefined();
    expect(screen.getByText("admin")).toBeDefined();
    expect(sent).toHaveLength(1);
    expect(sent[0].path).toBe("/api/v1/iam/tokens/verify");
    expect(sent[0].body).toEqual({ token: "abc.def.ghi" });
  });

  it("shows an invalid verdict with the server's reason", async () => {
    stubControlPlane({ [route]: ok({ valid: false, reason: "token expired" }) });
    render(withControlPlane(<TokenVerifyCard tenantId="tenant-a" />));

    paste("abc.def.ghi");
    await verify();

    expect(await screen.findByText("Invalid")).toBeDefined();
    expect(screen.getByText("token expired")).toBeDefined();
    expect(screen.queryByText("Valid")).toBeNull();
  });

  it("withholds Verify when the server does not offer the op", async () => {
    caps.capability.mockImplementation((op: string) =>
      op === verifyOp ? { enabled: false, reason: "not-configured: iam" } : { enabled: true }
    );
    const sent = stubControlPlane({ [route]: ok({ valid: true }) });
    render(withControlPlane(<TokenVerifyCard tenantId="tenant-a" />));

    paste("abc.def.ghi");
    const button = screen.getByRole("button", { name: /Verify/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: iam");
    expect(button.getAttribute("data-capability-op")).toBe(verifyOp);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");

    await verify();
    expect(sent).toHaveLength(0);
    expect(screen.queryByText("Valid")).toBeNull();
  });

  it("disables Verify without a signed-in tenant", async () => {
    const sent = stubControlPlane({ [route]: ok({ valid: true }) });
    render(withControlPlane(<TokenVerifyCard tenantId={null} />));

    paste("abc.def.ghi");
    const button = screen.getByRole("button", { name: /Verify/ }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("Sign in to a tenant to verify tokens");

    await verify();
    expect(sent).toHaveLength(0);
    expect(screen.queryByText("Valid")).toBeNull();
  });

  it("shows a refused request as an error, never a stale verdict", async () => {
    serve(() => stubControlPlane({ [route]: ok({ valid: true, subject: "u-1" }) }));
    render(withNoRetry(<TokenVerifyCard tenantId="tenant-a" />));

    paste("abc.def.ghi");
    await verify();
    expect(await screen.findByText("Valid")).toBeDefined();

    serve(() => stubControlPlane({ [route]: refused(500, "verifier down") }));
    await verify();

    expect(await screen.findByText(/verifier down/)).toBeDefined();
    expect(screen.queryByText("Valid")).toBeNull();
  });
});
