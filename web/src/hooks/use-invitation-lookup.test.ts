import { cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// One stable service: a new object per render would re-run the hook's effect.
const invitations = { get: vi.fn(), getByToken: vi.fn(), accept: vi.fn() };
const client = { invitation: invitations };

vi.mock("trusted-platform-sdk", () => ({ usePlatformClient: () => client }));

import {
  acceptInvitation,
  fetchInvitation,
  fetchInvitationByToken,
  isPendingInvitation,
  useInvitationLookup,
  type InvitationClient,
} from "./use-invitation-lookup";

const svc = invitations as unknown as InvitationClient;

const invitation = {
  id: "inv-1",
  email: "invitee@example.com",
  role: "member",
  status: "INVITATION_STATUS_PENDING",
};

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => {
      throw new Error("the invitation hook must not call fetch");
    })
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("fetchInvitationByToken", () => {
  it("returns data.invitation", async () => {
    invitations.getByToken.mockResolvedValue({ success: true, data: { invitation } });

    await expect(fetchInvitationByToken(svc, "tok")).resolves.toEqual(invitation);
    expect(invitations.getByToken).toHaveBeenCalledWith("tok");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses a response without an invitation", async () => {
    invitations.getByToken.mockResolvedValue({ success: true, data: {} });

    await expect(fetchInvitationByToken(svc, "tok")).rejects.toThrow(/no invitation/i);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("throws the SDK error message", async () => {
    invitations.getByToken.mockResolvedValue({
      success: false,
      error: { code: "HTTP_404", message: "invitation not found", status: 404 },
    });

    await expect(fetchInvitationByToken(svc, "tok")).rejects.toThrow(/invitation not found/);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("fetchInvitation", () => {
  it("reads the invitation by id through the SDK", async () => {
    invitations.get.mockResolvedValue({ success: true, data: { invitation } });

    await expect(fetchInvitation(svc, "inv-1")).resolves.toEqual(invitation);
    expect(invitations.get).toHaveBeenCalledWith("inv-1");
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("acceptInvitation", () => {
  it("sends {token, userId} and nothing else", async () => {
    invitations.accept.mockResolvedValue({ success: true, data: { success: true, tenantId: "t1" } });

    await expect(acceptInvitation(svc, "tok", "user-1")).resolves.toEqual({
      success: true,
      tenantId: "t1",
    });
    expect(invitations.accept).toHaveBeenCalledWith({ token: "tok", userId: "user-1" });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("useInvitationLookup", () => {
  it("loads by token through getByToken", async () => {
    invitations.getByToken.mockResolvedValue({ success: true, data: { invitation } });

    const { result } = renderHook(() => useInvitationLookup({ token: "tok" }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.invitation).toEqual(invitation);
    expect(result.current.error).toBeNull();
    expect(invitations.getByToken).toHaveBeenCalledWith("tok");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("loads by id through get", async () => {
    invitations.get.mockResolvedValue({ success: true, data: { invitation } });

    const { result } = renderHook(() => useInvitationLookup({ id: "inv-1" }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.invitation).toEqual(invitation);
    expect(invitations.get).toHaveBeenCalledWith("inv-1");
    expect(invitations.getByToken).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
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
