import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2063: useRegistry drives the four registry operations (Status, List,
// Inspect, Delete) through the SDK's RegistryService, never a hand-written
// fetch.

const sdk = {
  getStatus: vi.fn(),
  listTags: vi.fn(),
  inspect: vi.fn(),
  deleteManifest: vi.fn(),
};
const apiClient = { marker: "api-client" };
const constructedWith: unknown[] = [];

vi.mock("trusted-platform-sdk", async (importOriginal) => ({
  ...(await importOriginal<typeof import("trusted-platform-sdk")>()),
  usePlatformClient: () => ({ getApiClient: () => apiClient }),
  RegistryService: class {
    constructor(client: unknown) {
      constructedWith.push(client);
    }
    getStatus = sdk.getStatus;
    listTags = sdk.listTags;
    inspect = sdk.inspect;
    deleteManifest = sdk.deleteManifest;
  },
}));

import { useRegistry } from "./use-registry";

const ok = <T,>(data: T) => ({ success: true, data });
const fail = (message: string) => ({ success: false, error: { message } });

describe("useRegistry", () => {
  const fetchSpy = vi.fn();

  beforeEach(() => {
    constructedWith.length = 0;
    vi.stubGlobal("fetch", fetchSpy);
    sdk.getStatus.mockResolvedValue(ok({ Health: 1, Version: "3.0.0", ReadOnly: false }));
    sdk.listTags.mockResolvedValue(ok({ name: "team/app", tags: ["v1"] }));
    sdk.inspect.mockResolvedValue(
      ok({ Artifact: { Repository: "team/app", Tag: "v1", Digest: "sha256:abc", Size: 42 } })
    );
    sdk.deleteManifest.mockResolvedValue({ success: true });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("loads the status through the SDK on the platform client's API client", async () => {
    const { result } = renderHook(() => useRegistry());
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    expect(sdk.getStatus).toHaveBeenCalled();
    expect(constructedWith).toContain(apiClient);
    expect(result.current.status?.Version).toBe("3.0.0");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("reports the server's status error", async () => {
    sdk.getStatus.mockResolvedValue(fail("registry down"));
    const { result } = renderHook(() => useRegistry());
    await waitFor(() => expect(result.current.isStatusLoading).toBe(false));

    expect(result.current.status).toBeNull();
    expect(result.current.statusError).toBe("registry down");
  });

  it("lists tags through the SDK", async () => {
    const { result } = renderHook(() => useRegistry());
    await act(() => result.current.listTags("team/app"));

    expect(sdk.listTags).toHaveBeenCalledWith("team/app");
    expect(result.current.tags).toEqual({ name: "team/app", tags: ["v1"] });
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("keeps the list error and clears the tags", async () => {
    sdk.listTags.mockResolvedValue(fail("NAME_UNKNOWN"));
    const { result } = renderHook(() => useRegistry());
    await act(() => result.current.listTags("team/none"));

    expect(result.current.tags).toBeNull();
    expect(result.current.tagsError).toBe("NAME_UNKNOWN");
  });

  it("inspects a tag through the SDK", async () => {
    const { result } = renderHook(() => useRegistry());
    await act(() => result.current.inspect("team/app", "v1"));

    expect(sdk.inspect).toHaveBeenCalledWith("team/app", "v1");
    expect(result.current.inspection?.Artifact?.Digest).toBe("sha256:abc");
    expect(result.current.inspectError).toBeNull();
  });

  it("keeps the inspect error", async () => {
    sdk.inspect.mockResolvedValue(fail("not found"));
    const { result } = renderHook(() => useRegistry());
    await act(() => result.current.inspect("team/app", "gone"));

    expect(result.current.inspection).toBeNull();
    expect(result.current.inspectError).toBe("not found");
  });

  it("deletes a manifest through the SDK, then lists the tags again", async () => {
    const { result } = renderHook(() => useRegistry());
    await act(() => result.current.deleteManifest("team/app", "v1"));

    expect(sdk.deleteManifest).toHaveBeenCalledWith("team/app", "v1");
    expect(sdk.listTags).toHaveBeenCalledWith("team/app");
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("throws the server's delete error", async () => {
    sdk.deleteManifest.mockResolvedValue(fail("DENIED"));
    const { result } = renderHook(() => useRegistry());

    await expect(result.current.deleteManifest("team/app", "v1")).rejects.toThrow("DENIED");
    expect(sdk.listTags).not.toHaveBeenCalled();
  });
});
