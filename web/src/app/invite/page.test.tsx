import * as React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";

// #2023 Codex round 1: the passkey sign-up redirects a browser with a session
// to /dashboard before it processes the invitation, so a signed-in invitee must
// not be offered "Join workspace" from /invite/?token=...
// #2233: the page loads the invitation through the SDK client
// (useInvitationByToken), not a hand-written fetch.

let sessionToken: string | null = null;

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("token=tok-1"),
}));

vi.mock("@/hooks/use-session-token", () => ({
  useSessionToken: () => sessionToken,
}));

import InvitePage from "./page";

const route = "GET /api/v1/invitations/token/tok-1";

const pending = ok({
  invitation: {
    id: "inv-1",
    email: "invited@example.com",
    role: "member",
    status: "INVITATION_STATUS_PENDING",
    tenantName: "Acme",
  },
});

function jwt(claims: Record<string, unknown>): string {
  const b64 = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(claims)}.sig`;
}

function firstFetchUrl(): string {
  const input = vi.mocked(fetch).mock.calls[0][0];
  return input instanceof Request ? input.url : String(input);
}

describe("InvitePage", () => {
  beforeEach(() => {
    sessionToken = null;
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("signed out: offers the passkey sign-up join link, loaded through the SDK client", async () => {
    const sent = stubControlPlane({ [route]: pending });
    render(withControlPlane(<InvitePage />));
    const link = await screen.findByTestId("invite-join");
    const href = link.getAttribute("href") ?? "";
    expect(href.startsWith("/auth/webauthn/?invitation=tok-1")).toBe(true);
    expect(href).toContain("tenant_name=Acme");
    expect(screen.queryByTestId("invite-signed-in")).toBeNull();
    expect(sent).toHaveLength(1);
    expect(firstFetchUrl().startsWith("https://control-plane.test/api/v1/invitations/token/tok-1")).toBe(true);
  });

  it("signed in: explains the existing-account limitation instead of a dead-end link", async () => {
    stubControlPlane({ [route]: pending });
    sessionToken = jwt({ sub: "alice@example.com", user_id: "alice@example.com" });
    render(withControlPlane(<InvitePage />));
    const notice = await screen.findByTestId("invite-signed-in");
    expect(screen.queryByTestId("invite-join")).toBeNull();
    expect(notice.getAttribute("role")).toBe("status");
    expect(notice.textContent).toContain("alice@example.com");
    expect(notice.textContent).toContain("existing account cannot join this workspace from an invitation link");
  });

  it("shows the SDK error and offers no join link when the invitation is not found", async () => {
    stubControlPlane({ [route]: refused(404, "invitation not found") });
    render(withControlPlane(<InvitePage />));
    await waitFor(() => expect(screen.getByTestId("invite-error").textContent).toContain("invitation not found"));
    expect(screen.queryByTestId("invite-join")).toBeNull();
  });
});
