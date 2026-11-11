import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuthProvider } from "@/contexts/AuthContext";
import type { AuthFactor } from "@/types/auth-factors";
import { authFactorsApi } from "@/utils/auth-factors-api";
import AccountSecurityPage from "./page";

// #435: the page loads its factors through the SDK's useApi. These tests drive
// the load through a stubbed fetch, the same boundary the browser crosses.

function jwtFor(payload: Record<string, unknown>): string {
  const b64 = (o: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64(payload)}.sig`;
}

const userToken = jwtFor({
  sub: "user-1",
  email: "user@example.com",
  tenant_id: "tenant-9",
  is_tenant_owner: false,
  roles: [],
  exp: Math.floor(Date.now() / 1000) + 3600,
});

const factor: AuthFactor = {
  id: "factor-1",
  user_id: "user-1",
  type: "fido2",
  label: "Desk YubiKey",
  metadata: {},
  registered_at: "2026-10-01T00:00:00Z",
  last_used_at: null,
  revoked_at: null,
  created_by: "self",
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderPage() {
  return render(
    <AuthProvider>
      <AccountSecurityPage />
    </AuthProvider>
  );
}

describe("AccountSecurityPage factor loading", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("lists the signed-in user's factors", async () => {
    document.cookie = `jwt=${userToken}; path=/`;
    fetchMock.mockResolvedValue(jsonResponse(200, { factors: [factor], total: 1 }));

    renderPage();

    expect(await screen.findByText("Desk YubiKey")).toBeTruthy();
    expect(String(fetchMock.mock.calls[0][0])).toMatch(/\/api\/v1\/users\/user-1\/factors$/);
  });

  it("does not request factors before a user is known", () => {
    renderPage();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(screen.getByLabelText("Loading factors")).toBeTruthy();
  });

  it("shows the load error and recovers on retry", async () => {
    document.cookie = `jwt=${userToken}; path=/`;
    fetchMock
      .mockResolvedValueOnce(jsonResponse(500, { error: "factor store unavailable" }))
      .mockResolvedValueOnce(jsonResponse(200, { factors: [factor], total: 1 }));

    renderPage();

    expect(await screen.findByText("Failed to load factors")).toBeTruthy();
    expect(screen.getByText("factor store unavailable")).toBeTruthy();

    await act(async () => screen.getByText("Retry").click());

    expect(await screen.findByText("Desk YubiKey")).toBeTruthy();
    expect(screen.queryByText("Failed to load factors")).toBeNull();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("AccountSecurityPage session policy", () => {
  const fetchMock = vi.fn<typeof fetch>();

  const ownerToken = jwtFor({
    sub: "owner-1",
    email: "owner@example.com",
    tenant_id: "tenant-9",
    is_tenant_owner: true,
    roles: [],
    exp: Math.floor(Date.now() / 1000) + 3600,
  });

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    document.cookie = "jwt=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
  });

  it("offers no MFA-policy toggle while the server refuses it", async () => {
    document.cookie = `jwt=${ownerToken}; path=/`;
    fetchMock.mockResolvedValue(jsonResponse(200, { factors: [], total: 0 }));
    const setPolicy = vi.spyOn(authFactorsApi, "setMFAPolicy");

    renderPage();

    await screen.findByText("Session policy");
    const toggle = document.getElementById("require-mfa");
    expect(toggle).not.toBeNull();
    expect(toggle?.hasAttribute("disabled")).toBe(true);

    await act(async () => {
      fireEvent.click(toggle as HTMLElement);
    });

    expect(setPolicy).not.toHaveBeenCalled();
    expect(
      fetchMock.mock.calls.some(([url]) => String(url).includes("mfa-policy"))
    ).toBe(false);
  });
});
