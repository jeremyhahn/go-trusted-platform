import * as React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";

// #2233: the admin invitation detail page loads the invitation through the
// SDK client (useInvitationById), not a hand-written fetch.

let search = "id=inv-1";

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(search),
}));

import InvitationDetailPage from "./page";

const route = "GET /api/v1/invitations/inv-1";

function firstFetchUrl(): string {
  const input = vi.mocked(fetch).mock.calls[0][0];
  return input instanceof Request ? input.url : String(input);
}

describe("InvitationDetailPage", () => {
  beforeEach(() => {
    search = "id=inv-1";
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows the invitation the SDK client loaded", async () => {
    stubControlPlane({
      [route]: ok({
        invitation: {
          id: "inv-1",
          email: "a@example.com",
          role: "admin",
          status: "INVITATION_STATUS_PENDING",
          expiresAt: "2099-01-01T00:00:00Z",
        },
      }),
    });
    render(withControlPlane(<InvitationDetailPage />));
    expect((await screen.findByTestId("invitation-detail-email")).textContent).toBe("a@example.com");
    expect(screen.getByTestId("invitation-detail-status").textContent).toBe("pending");
    expect(screen.getByText("Expires")).toBeTruthy();
    expect(firstFetchUrl().startsWith("https://control-plane.test/api/v1/invitations/inv-1")).toBe(true);
  });

  it("shows the SDK error when the invitation is not found", async () => {
    stubControlPlane({ [route]: refused(404, "invitation not found") });
    render(withControlPlane(<InvitationDetailPage />));
    await waitFor(() =>
      expect(screen.getByTestId("invitation-detail-error").textContent).toContain("invitation not found")
    );
  });

  it("sends no request and says so when no invitation is named", async () => {
    search = "";
    const sent = stubControlPlane({});
    render(withControlPlane(<InvitationDetailPage />));
    expect((await screen.findByTestId("invitation-detail-error")).textContent).toBe("No invitation was named");
    expect(sent).toHaveLength(0);
  });
});
