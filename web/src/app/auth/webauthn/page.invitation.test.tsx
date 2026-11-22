import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";

import WebAuthnUI from "./page";

// An invitation link opens the passkey page with ?invitation=<token>; the page
// reads that invitation through GetInvitationByToken (no session needed).
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  useSearchParams: () => new URLSearchParams("invitation=tok-1"),
}));

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("WebAuthnUI invitation link", () => {
  it("the invitation link shows the invitation GetInvitationByToken returns", async () => {
    const sent = stubControlPlane({
      "GET /api/v1/invitations/token/tok-1": ok({
        invitation: {
          id: "42",
          token: "tok-1",
          tenantId: "7",
          email: "invitee@example.com",
          role: "admin",
          status: "pending",
          expiresAt: "2099-12-01T00:00:00Z",
          createdAt: "2026-11-20T00:00:00Z",
          invitedById: "1",
        },
      }),
    });

    render(withControlPlane(<WebAuthnUI />));

    const input = (await screen.findByLabelText("Email")) as HTMLInputElement;
    await vi.waitFor(() => expect(input.value).toBe("invitee@example.com"));
    expect(screen.getByText(/as admin/)).toBeTruthy();
    expect(sent.some((r) => r.method === "GET" && r.path === "/api/v1/invitations/token/tok-1")).toBe(true);
  });

  it("an invitation link the server refuses says the invitation is not valid", async () => {
    stubControlPlane({
      "GET /api/v1/invitations/token/tok-1": refused(404, "invitation not found"),
    });

    render(withControlPlane(<WebAuthnUI />));

    expect(await screen.findByText("This invitation is no longer valid.")).toBeTruthy();
    expect((screen.getByRole("button", { name: "Register" }) as HTMLButtonElement).disabled).toBe(false);
  });
});
