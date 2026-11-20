import { renderHook } from "@testing-library/react";
import type { ProvisioningSession } from "trusted-platform-sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createProfileAndFulfil,
  fulfilBlockedReason,
  provisioningSessionStatus,
  useProvisioningSession,
  type ProfileCreator,
} from "./use-provisioning-session";

type MutationFn = (create: ProfileCreator) => Promise<unknown>;
interface MutationOptions {
  onSuccess?: (...args: unknown[]) => void;
}

const sdk = vi.hoisted(() => ({
  getProvisioningSession: vi.fn(),
  fulfillProvisioningSession: vi.fn(),
  refetch: vi.fn(),
  apiData: undefined as unknown,
  apiFetcher: undefined as unknown,
  apiDeps: undefined as unknown,
  mutationFn: undefined as unknown,
  mutationOptions: undefined as unknown,
  mutationResult: { mutate: () => undefined, isLoading: false },
}));

vi.mock("trusted-platform-sdk", () => ({
  useDevice: () => ({
    getProvisioningSession: sdk.getProvisioningSession,
    fulfillProvisioningSession: sdk.fulfillProvisioningSession,
  }),
  useApi: (fetcher: unknown, deps: unknown) => {
    sdk.apiFetcher = fetcher;
    sdk.apiDeps = deps;
    return {
      data: sdk.apiData,
      error: undefined,
      isLoading: false,
      refetch: sdk.refetch,
    };
  },
  useMutation: (fn: unknown, options: unknown) => {
    sdk.mutationFn = fn;
    sdk.mutationOptions = options;
    return sdk.mutationResult;
  },
}));

const NOW = new Date("2026-11-20T12:00:00Z");
const session = (extra: Partial<ProvisioningSession> = {}) =>
  ({
    id: "sess-1",
    fulfilled: false,
    created_at: "2026-11-20T11:00:00Z",
    expires_at: "2026-11-20T13:00:00Z",
    ...extra,
  }) as ProvisioningSession;

describe("provisioningSessionStatus", () => {
  it("is fulfilled, expired or pending from the server's session", () => {
    expect(provisioningSessionStatus(session({ fulfilled: true }), NOW)).toBe("fulfilled");
    expect(
      provisioningSessionStatus(session({ expires_at: "2026-11-20T11:59:59Z" }), NOW)
    ).toBe("expired");
    expect(provisioningSessionStatus(session(), NOW)).toBe("pending");
  });
});

describe("fulfilBlockedReason", () => {
  it("allows a pending session", () => {
    expect(fulfilBlockedReason(session(), NOW)).toBeNull();
  });

  it("gives a reason for a missing, fulfilled or expired session", () => {
    expect(fulfilBlockedReason(undefined, NOW)).toMatch(/not loaded/i);
    expect(fulfilBlockedReason(session({ fulfilled: true }), NOW)).toMatch(/already fulfilled/i);
    expect(
      fulfilBlockedReason(session({ expires_at: "2026-11-20T11:00:00Z" }), NOW)
    ).toMatch(/expired/i);
  });
});

describe("createProfileAndFulfil", () => {
  beforeEach(() => vi.clearAllMocks());

  it("fulfils the session with the created profile's id", async () => {
    sdk.fulfillProvisioningSession.mockResolvedValue({ success: true });
    const device = { fulfillProvisioningSession: sdk.fulfillProvisioningSession };
    const reply = await createProfileAndFulfil(device, "sess-1", async () => "42");
    expect(sdk.fulfillProvisioningSession).toHaveBeenCalledWith({
      session_id: "sess-1",
      profile_id: "42",
    });
    expect(reply).toEqual({ success: true, data: { profileId: "42" } });
  });

  it("refuses, without a fulfil call, when the server returned no profile id", async () => {
    const device = { fulfillProvisioningSession: sdk.fulfillProvisioningSession };
    await expect(
      createProfileAndFulfil(device, "sess-1", async () => undefined)
    ).rejects.toThrow(/no profile id/i);
    expect(sdk.fulfillProvisioningSession).not.toHaveBeenCalled();
  });

  it("surfaces the server's fulfil refusal instead of reporting success", async () => {
    sdk.fulfillProvisioningSession.mockResolvedValue({
      success: false,
      error: { code: "NOT_FOUND", message: "session not found" },
    });
    const device = { fulfillProvisioningSession: sdk.fulfillProvisioningSession };
    await expect(
      createProfileAndFulfil(device, "sess-1", async () => "42")
    ).rejects.toThrow("session not found");
  });
});

describe("useProvisioningSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(NOW);
    sdk.apiData = session();
  });

  it("reads the session through GetSession for the given id", async () => {
    sdk.getProvisioningSession.mockResolvedValue({ success: true, data: session() });
    const { result } = renderHook(() => useProvisioningSession("sess-1"));
    expect(sdk.apiDeps).toEqual(["sess-1"]);
    await (sdk.apiFetcher as () => Promise<unknown>)();
    expect(sdk.getProvisioningSession).toHaveBeenCalledWith("sess-1");
    expect(result.current.session).toEqual(session());
    expect(result.current.status).toBe("pending");
    expect(result.current.fulfilBlockedReason).toBeNull();
    expect(result.current.fulfil).toBe(sdk.mutationResult);
  });

  it("fulfil creates the profile, fulfils and refetches the session", async () => {
    sdk.fulfillProvisioningSession.mockResolvedValue({ success: true });
    renderHook(() => useProvisioningSession("sess-1"));
    const reply = await (sdk.mutationFn as MutationFn)(async () => "7");
    expect(reply).toEqual({ success: true, data: { profileId: "7" } });
    expect(sdk.fulfillProvisioningSession).toHaveBeenCalledWith({
      session_id: "sess-1",
      profile_id: "7",
    });
    (sdk.mutationOptions as MutationOptions).onSuccess?.({ profileId: "7" }, undefined);
    expect(sdk.refetch).toHaveBeenCalled();
  });

  it("fulfil on an expired session creates no profile and calls no SDK method", async () => {
    sdk.apiData = session({ expires_at: "2026-11-20T11:00:00Z" });
    const { result } = renderHook(() => useProvisioningSession("sess-1"));
    expect(result.current.status).toBe("expired");
    const create = vi.fn(async () => "7");
    await expect((sdk.mutationFn as MutationFn)(create)).rejects.toThrow(/expired/i);
    expect(create).not.toHaveBeenCalled();
    expect(sdk.fulfillProvisioningSession).not.toHaveBeenCalled();
  });
});
