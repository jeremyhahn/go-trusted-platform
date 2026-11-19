import { afterEach, describe, expect, it, vi } from "vitest";
import {
  acceptInvitation,
  fetchInvitationByToken,
  isPendingInvitation,
} from "./use-invitation-lookup";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const invitation = {
  id: "inv-1",
  email: "invitee@example.com",
  role: "member",
  status: "INVITATION_STATUS_PENDING",
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchInvitationByToken", () => {
  it("unwraps the REST envelope's payload.invitation", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse({
        code: 200,
        success: true,
        payload: { invitation, timestamp: "2026-11-12T00:00:00Z" },
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchInvitationByToken("tok")).resolves.toEqual(invitation);
  });

  it("falls back to a bare {invitation} body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(jsonResponse({ invitation })));

    await expect(fetchInvitationByToken("tok")).resolves.toEqual(invitation);
  });

  it("refuses an envelope without an invitation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse({ code: 200, success: true, payload: {} }))
    );

    await expect(fetchInvitationByToken("tok")).rejects.toThrow(/no invitation/i);
  });
});

describe("acceptInvitation", () => {
  it("posts {token, user_id} and nothing else", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({ success: true }));
    vi.stubGlobal("fetch", fetchMock);

    await acceptInvitation("tok", "user-1");

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toEqual({ token: "tok", user_id: "user-1" });
  });
});

describe("isPendingInvitation", () => {
  it.each([
    ["pending", true],
    ["PENDING", true],
    ["INVITATION_STATUS_PENDING", true],
    ["invitation_status_pending", true],
    ["INVITATION_STATUS_ACCEPTED", false],
    ["accepted", false],
    ["", false],
  ])("%s -> %s", (status, want) => {
    expect(isPendingInvitation(status)).toBe(want);
  });
});
