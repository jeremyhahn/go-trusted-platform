import { renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2056: GetInvitation and GetInvitationByToken go through the SDK
// InvitationService, never a hand-written fetch, and the hooks module offers
// no AcceptInvitation call: AcceptInvitation marks an invitation accepted
// without adding the user to the tenant, so its control is gated off.

const service = {
  get: vi.fn(),
  getByToken: vi.fn(),
  accept: vi.fn(),
};

vi.mock("trusted-platform-sdk", () => ({
  useInvitation: () => ({ service }),
}));

import * as lookup from "./use-invitation-lookup";
import { isPendingInvitation, toInvitationDetail, useInvitationLookup } from "./use-invitation-lookup";

const invitation = {
  id: "inv-1",
  email: "invitee@example.com",
  role: "member",
  status: "INVITATION_STATUS_PENDING",
};

const fetchSpy = vi.fn();

beforeEach(() => {
  service.get.mockReset();
  service.getByToken.mockReset();
  service.accept.mockReset();
  fetchSpy.mockReset();
  vi.stubGlobal("fetch", fetchSpy);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("toInvitationDetail", () => {
  it("reads the invitation the SDK returns as {invitation}", () => {
    expect(toInvitationDetail({ invitation })).toEqual(invitation);
  });

  it("still unwraps a raw REST envelope's payload.invitation", () => {
    expect(
      toInvitationDetail({ code: 200, success: true, payload: { invitation, timestamp: "t" } })
    ).toEqual(invitation);
  });

  it("normalizes the protojson camelCase fields to snake_case", () => {
    const got = toInvitationDetail({
      invitation: {
        ...invitation,
        expiresAt: "2026-12-01T00:00:00Z",
        createdAt: "2026-11-12T00:00:00Z",
        tenantId: "t-1",
        tenantName: "Acme",
      },
    });
    expect(got.expires_at).toBe("2026-12-01T00:00:00Z");
    expect(got.created_at).toBe("2026-11-12T00:00:00Z");
    expect(got.tenant_id).toBe("t-1");
    expect(got.tenant_name).toBe("Acme");
  });

  it("refuses a body without an invitation", () => {
    expect(() => toInvitationDetail({})).toThrow(/no invitation/i);
  });
});

describe("useInvitationLookup", () => {
  it("by id: calls InvitationService.get through the SDK, never fetch", async () => {
    service.get.mockResolvedValue({ success: true, data: { invitation } });
    const { result } = renderHook(() => useInvitationLookup({ id: "inv-1" }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(service.get).toHaveBeenCalledWith("inv-1");
    expect(service.getByToken).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.current.invitation).toEqual(invitation);
    expect(result.current.error).toBeNull();
  });

  it("by token: calls InvitationService.getByToken through the SDK, never fetch", async () => {
    service.getByToken.mockResolvedValue({ success: true, data: { invitation } });
    const { result } = renderHook(() => useInvitationLookup({ token: "tok" }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(service.getByToken).toHaveBeenCalledWith("tok");
    expect(service.get).not.toHaveBeenCalled();
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(result.current.invitation).toEqual(invitation);
  });

  it("shows the server's refusal message", async () => {
    service.getByToken.mockResolvedValue({
      success: false,
      error: { code: 404, message: "invitation not found" },
    });
    const { result } = renderHook(() => useInvitationLookup({ token: "gone" }));
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.invitation).toBeNull();
    expect(result.current.error).toBe("invitation not found");
  });

  it("names nothing: stays idle and calls no service", () => {
    const { result } = renderHook(() => useInvitationLookup({}));
    expect(result.current.loading).toBe(false);
    expect(result.current.error).toMatch(/no invitation/i);
    expect(service.get).not.toHaveBeenCalled();
    expect(service.getByToken).not.toHaveBeenCalled();
  });
});

describe("AcceptInvitation", () => {
  it("the hooks module has no hand-written accept call", () => {
    expect("acceptInvitation" in lookup).toBe(false);
    expect("fetchInvitation" in lookup).toBe(false);
    expect("fetchInvitationByToken" in lookup).toBe(false);
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
