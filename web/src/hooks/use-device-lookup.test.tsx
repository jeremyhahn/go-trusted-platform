import { act, renderHook, waitFor } from "@testing-library/react";
import type { ComponentProps, ReactNode } from "react";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useDeviceLookup } from "./use-device-lookup";

type ProviderChildren = ComponentProps<typeof PlatformProvider>["children"];

// #2048: the device row's operations through the lookup hook. fetch is the
// stub, the boundary the browser crosses, answering with the envelopes the
// webservice writes, so each test pins the route and verb the SDK sends.

const toast = vi.fn();
vi.mock("./use-toast", () => ({
  useToast: () => ({ toast }),
}));

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function ok(payload: unknown): Response {
  return jsonResponse(200, { code: 200, error: "", success: true, payload });
}

function failure(status: number, error: string): Response {
  return jsonResponse(status, { code: status, error, success: false });
}

const profile = { id: "7", name: "edge-a", model: "Board-A", mac_address: "52:54:00:00:00:0a" };

describe("useDeviceLookup", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderLookup() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    // The SDK resolves its own @types/react: type children as its provider does.
    const wrapper = ({ children }: { children: ReactNode }) => (
      <PlatformProvider client={client}>{children as ProviderChildren}</PlatformProvider>
    );
    return renderHook(() => useDeviceLookup(), { wrapper });
  }

  function calls(method: string, suffix: string) {
    return fetchMock.mock.calls.filter(([input, init]) => {
      const url = new URL(String(input));
      return (init?.method ?? "GET") === method && url.pathname.endsWith(suffix);
    });
  }

  beforeEach(() => {
    toast.mockReset();
    fetchMock.mockReset();
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      const path = url.pathname;
      if (method === "GET" && path.endsWith("/devices/count")) return Promise.resolve(ok({ count: 3 }));
      if (method === "GET" && path.endsWith("/device/profiles/count")) return Promise.resolve(ok({ count: 2 }));
      if (method === "GET" && path.endsWith("/devices/serial/SN-1")) {
        return Promise.resolve(ok({ id: "5", serial: "SN-1", model: "Board-A" }));
      }
      if (method === "PUT" && path.endsWith("/devices/5")) {
        return Promise.resolve(ok({ id: "5", serial: "SN-1", model: "Board-B" }));
      }
      // GET /device/profiles/{id} answers the flat ProfileFullResponse.
      if (method === "GET" && path.endsWith("/device/profiles/7")) return Promise.resolve(ok(profile));
      if (method === "GET" && path.endsWith("/device/profiles/mac/52%3A54%3A00%3A00%3A00%3A0a")) {
        return Promise.resolve(ok(profile));
      }
      if (method === "GET" && path.endsWith("/device/profiles/serial/SN-1")) return Promise.resolve(ok(profile));
      if (method === "POST" && path.endsWith("/device/profiles/match")) return Promise.resolve(ok(profile));
      if (method === "PUT" && path.endsWith("/device/profiles/7")) {
        return Promise.resolve(ok({ ...profile, name: "edge-b" }));
      }
      if (method === "POST" && path.endsWith("/device/activate-json")) {
        return Promise.resolve(ok({ status: "activated", vlan: 20 }));
      }
      return Promise.resolve(failure(404, `no route ${method} ${path}`));
    });
  });

  it("reads the device and profile counts on mount", async () => {
    const { result } = renderLookup();

    await waitFor(() => expect(result.current.deviceCount.data?.count).toBe(3));
    await waitFor(() => expect(result.current.profileCount.data?.count).toBe(2));
  });

  it("finds a device by serial and saves its model with PUT /devices/{id}", async () => {
    const { result } = renderLookup();

    let found: unknown;
    await act(async () => {
      found = await result.current.findDeviceBySerial.mutateAsync("SN-1");
    });
    expect(found).toMatchObject({ id: "5", serial: "SN-1" });

    await act(async () => {
      await result.current.updateDevice.mutateAsync({ id: "5", model: "Board-B" });
    });
    const [put] = calls("PUT", "/devices/5");
    expect(put).toBeDefined();
    expect(JSON.parse(String(put[1]?.body)).device).toMatchObject({ id: "5", model: "Board-B" });
    expect(toast).toHaveBeenCalledWith(expect.objectContaining({ title: "Device updated" }));
  });

  it("gets a profile by ID from GET /device/profiles/{id}", async () => {
    const { result } = renderLookup();

    let found: unknown;
    await act(async () => {
      found = await result.current.getProfile.mutateAsync("7");
    });

    expect(calls("GET", "/device/profiles/7")).toHaveLength(1);
    expect(found).toMatchObject({ id: "7", name: "edge-a" });
  });

  it("finds a profile by MAC, by serial and by match criteria", async () => {
    const { result } = renderLookup();

    await act(async () => {
      await result.current.findProfileByMAC.mutateAsync("52:54:00:00:00:0a");
      await result.current.findProfileBySerial.mutateAsync("SN-1");
      await result.current.findMatchingProfile.mutateAsync({ model: "Board-A" });
    });

    expect(calls("GET", "/device/profiles/mac/52%3A54%3A00%3A00%3A00%3A0a")).toHaveLength(1);
    expect(calls("GET", "/device/profiles/serial/SN-1")).toHaveLength(1);
    const [match] = calls("POST", "/device/profiles/match");
    expect(JSON.parse(String(match[1]?.body))).toEqual({ model: "Board-A" });
  });

  it("saves a profile with PUT /device/profiles/{id}", async () => {
    const { result } = renderLookup();

    let saved: unknown;
    await act(async () => {
      saved = await result.current.updateProfile.mutateAsync({ ...profile, name: "edge-b" } as never);
    });

    expect(calls("PUT", "/device/profiles/7")).toHaveLength(1);
    expect(saved).toMatchObject({ name: "edge-b" });
  });

  it("activates through POST /device/activate-json with the snake_case MAC", async () => {
    const { result } = renderLookup();

    await act(async () => {
      await result.current.activateDevice.mutateAsync({ serial: "SN-1", macAddress: "52:54:00:00:00:0a" });
    });

    const [post] = calls("POST", "/device/activate-json");
    expect(JSON.parse(String(post[1]?.body))).toEqual({ serial: "SN-1", mac_address: "52:54:00:00:00:0a" });
  });

  it("toasts the server's message when a lookup fails", async () => {
    const { result } = renderLookup();

    await act(async () => {
      await result.current.getProfile.mutateAsync("99").catch(() => undefined);
    });

    expect(toast).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Profile lookup failed", variant: "destructive" })
    );
  });
});
