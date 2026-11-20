/**
 * The fulfil mutation through the SDK's real useMutation (#2046 Codex): the
 * profile creator travels inside an object, so React never takes it for a
 * state updater and one submit creates exactly one profile.
 */
import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useProvisioningSession } from "./use-provisioning-session";

const sdk = vi.hoisted(() => ({
  getProvisioningSession: vi.fn(),
  fulfillProvisioningSession: vi.fn(),
  refetch: vi.fn(),
}));

vi.mock("trusted-platform-sdk", async () => {
  const actual = await vi.importActual<typeof import("trusted-platform-sdk")>("trusted-platform-sdk");
  return {
    ...actual,
    useDevice: () => ({
      getProvisioningSession: sdk.getProvisioningSession,
      fulfillProvisioningSession: sdk.fulfillProvisioningSession,
    }),
    useApi: () => ({
      data: {
        id: "sess-1",
        fulfilled: false,
        created_at: "2026-11-20T11:00:00Z",
        expires_at: "2999-01-01T00:00:00Z",
      },
      error: undefined,
      isLoading: false,
      refetch: sdk.refetch,
    }),
  };
});

vi.mock("@/contexts/AuthContext", () => ({
  useOptionalAuth: () => ({
    user: { id: "u1", email: "a@example.test", tenantId: null, isTenantOwner: false, roles: ["admin"] },
  }),
}));

describe("useProvisioningSession fulfil (real useMutation)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("one submit calls the profile creator once and FulfillSession once", async () => {
    sdk.fulfillProvisioningSession.mockResolvedValue({ success: true });
    const create = vi.fn(async () => "42");
    const { result } = renderHook(() => useProvisioningSession("sess-1"));

    let reply: unknown;
    await act(async () => {
      reply = await result.current.fulfil.mutateAsync({ create });
    });

    expect(reply).toEqual({ profileId: "42" });
    expect(create).toHaveBeenCalledTimes(1);
    expect(sdk.fulfillProvisioningSession).toHaveBeenCalledTimes(1);
    expect(sdk.fulfillProvisioningSession).toHaveBeenCalledWith({
      session_id: "sess-1",
      profile_id: "42",
    });
  });
});
