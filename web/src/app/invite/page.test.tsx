import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2023 Codex round 1: the passkey sign-up redirects a browser with a session
// to /dashboard before it processes the invitation, so a signed-in invitee must
// not be offered "Join workspace" from /invite/?token=...

let sessionToken: string | null = null;

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams("token=tok-1"),
}));

vi.mock("@/hooks/use-session-token", () => ({
  useSessionToken: () => sessionToken,
}));

vi.mock("@/hooks", () => ({
  useInvitationLookup: () => ({
    invitation: {
      email: "invited@example.com",
      role: "member",
      status: "pending",
      tenant_name: "Acme",
    },
    loading: false,
    error: null,
  }),
  isPendingInvitation: (s: string) => s === "pending",
}));

import InvitePage from "./page";

function jwt(claims: Record<string, unknown>): string {
  const b64 = (v: unknown) =>
    btoa(JSON.stringify(v)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${b64({ alg: "EdDSA", typ: "JWT" })}.${b64(claims)}.sig`;
}

describe("InvitePage", () => {
  beforeEach(() => {
    sessionToken = null;
  });
  afterEach(() => cleanup());

  it("signed out: offers the passkey sign-up join link", () => {
    render(<InvitePage />);
    const link = screen.getByTestId("invite-join");
    expect(link.getAttribute("href")?.startsWith("/auth/webauthn/?invitation=tok-1")).toBe(true);
    expect(screen.queryByTestId("invite-signed-in")).toBeNull();
  });

  it("signed in: explains the existing-account limitation instead of a dead-end link", () => {
    sessionToken = jwt({ sub: "alice@example.com", user_id: "alice@example.com" });
    render(<InvitePage />);
    expect(screen.queryByTestId("invite-join")).toBeNull();
    const notice = screen.getByTestId("invite-signed-in");
    expect(notice.getAttribute("role")).toBe("status");
    expect(notice.textContent).toContain("alice@example.com");
    expect(notice.textContent).toContain("existing account cannot join this workspace from an invitation link");
  });
});
