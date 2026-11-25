import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  FACTOR_ADD_OP,
  FACTOR_RELABEL_OP,
  FACTOR_REMOVE_OP,
  FACTOR_ROTATE_OP,
} from "@/components/security/factor-list";
import { AuthProvider } from "@/contexts/AuthContext";
import { withControlPlane } from "@/test/control-plane-fetch";
import type { AuthFactor } from "@/types/auth-factors";
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

// The page's gated controls need a PlatformProvider (#2033 item 5).
function renderPage() {
  return render(
    withControlPlane(
      <AuthProvider>
        <AccountSecurityPage />
      </AuthProvider>
    )
  );
}

const ALL_FACTOR_OPS = [FACTOR_ADD_OP, FACTOR_RELABEL_OP, FACTOR_ROTATE_OP, FACTOR_REMOVE_OP];

// The server's capabilities listing: only the ops in enabled are offered.
function capabilitiesResponse(enabled: string[]): Response {
  const capabilities = enabled.map((op) => ({ op, kind: "route", enabled: true }));
  return jsonResponse(200, {
    code: 200,
    success: true,
    payload: { capabilities, total: capabilities.length, enabled: capabilities.length },
  });
}

describe("AccountSecurityPage factor loading", () => {
  // fetchMock sees only the factor requests; the capabilities listing is
  // answered by URL from offered, so every fetchMock assertion is about the
  // factors path.
  const fetchMock = vi.fn<typeof fetch>();
  let offered: string[] = ALL_FACTOR_OPS;

  beforeEach(() => {
    fetchMock.mockReset();
    offered = ALL_FACTOR_OPS;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.includes("/api/v1/capabilities")) {
          return capabilitiesResponse(offered);
        }
        return fetchMock(input, init);
      })
    );
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

  it("disables Add factor when the server does not offer it", async () => {
    document.cookie = `jwt=${userToken}; path=/`;
    offered = [FACTOR_RELABEL_OP, FACTOR_ROTATE_OP, FACTOR_REMOVE_OP];
    fetchMock.mockResolvedValue(jsonResponse(200, { factors: [factor], total: 1 }));

    renderPage();

    expect(await screen.findByText("Desk YubiKey")).toBeTruthy();
    const add = screen.getByRole("button", { name: "Add authentication factor" }) as HTMLButtonElement;
    await waitFor(() => expect(add.getAttribute("data-capability-enabled")).toBe("false"));
    expect(add.disabled).toBe(true);
  });
});
