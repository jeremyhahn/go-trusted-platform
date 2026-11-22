import type { ReactNode } from "react";
import { cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import * as hooks from "./index";
import { useCeremony } from "./use-ceremony";

// #2042: useCeremony() drives the seven CeremonyService operations through
// the SDK's client.ceremony, never a hand-written fetch.

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function ok(payload: unknown): Response {
  return jsonResponse(200, { code: 200, error: "", success: true, payload });
}

type ProviderChildren = Parameters<typeof PlatformProvider>[0]["children"];

describe("useCeremony", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let client: PlatformClient;

  function renderCeremony() {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <PlatformProvider client={client}>{children as ProviderChildren}</PlatformProvider>
    );
    return renderHook(() => useCeremony(), { wrapper });
  }

  beforeEach(() => {
    fetchMock.mockReset();
    client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    cleanup();
  });

  describe("each method calls its client.ceremony method with the request", () => {
    it("init", async () => {
      const reply = { success: true, data: { ceremonyId: "c-1", adminPrivateKeyPem: "k" } };
      const spy = vi.spyOn(client.ceremony, "init").mockResolvedValue(reply as never);
      const request = { soPin: "1234", userPin: "5678", threshold: "3-of-5", hostname: "ca.test" };
      const { result } = renderCeremony();
      await expect(result.current.init(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("status", async () => {
      const reply = { success: true, data: { ceremonyId: "c-1", state: "CEREMONY_STATE_COMPLETE" } };
      const spy = vi.spyOn(client.ceremony, "status").mockResolvedValue(reply as never);
      const { result } = renderCeremony();
      await expect(result.current.status()).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("claimCertBegin", async () => {
      const reply = { success: true, data: { nonce: "bm9uY2U=" } };
      const spy = vi.spyOn(client.ceremony, "claimCertBegin").mockResolvedValue(reply as never);
      const request = { username: "officer-1", slot: "9a" };
      const { result } = renderCeremony();
      await expect(result.current.claimCertBegin(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("claimCertComplete", async () => {
      const reply = { success: true, data: { certificatePem: "cert" } };
      const spy = vi.spyOn(client.ceremony, "claimCertComplete").mockResolvedValue(reply as never);
      const request = { username: "officer-1", nonce: "bm9uY2U=", signature: "c2ln" };
      const { result } = renderCeremony();
      await expect(result.current.claimCertComplete(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("claimShareBegin", async () => {
      const reply = { success: true, data: { nonce: "bm9uY2U=" } };
      const spy = vi.spyOn(client.ceremony, "claimShareBegin").mockResolvedValue(reply as never);
      const request = { username: "officer-1" };
      const { result } = renderCeremony();
      await expect(result.current.claimShareBegin(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("claimShareComplete", async () => {
      const reply = { success: true, data: { share: "c2hhcmU=" } };
      const spy = vi.spyOn(client.ceremony, "claimShareComplete").mockResolvedValue(reply as never);
      const request = { username: "officer-1", nonce: "bm9uY2U=", signature: "c2ln" };
      const { result } = renderCeremony();
      await expect(result.current.claimShareComplete(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("signCSR", async () => {
      const reply = { success: true, data: { certificatePem: "cert" } };
      const spy = vi.spyOn(client.ceremony, "signCSR").mockResolvedValue(reply as never);
      const request = { username: "officer-1", soPin: "1234", csrPem: "-----BEGIN CERTIFICATE REQUEST-----" };
      const { result } = renderCeremony();
      await expect(result.current.signCSR(request)).resolves.toBe(reply);
      expect(spy).toHaveBeenCalledTimes(1);
      expect(spy).toHaveBeenCalledWith(request);
      expect(fetchMock).not.toHaveBeenCalled();
    });
  });

  it("status gets /api/v1/ceremony/status through the SDK", async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(
        ok({
          ceremonyId: "c-1",
          state: "CEREMONY_STATE_IN_PROGRESS",
          threshold: "3-of-5",
          officersEnrolled: 1,
          officersRequired: 5,
        })
      )
    );
    const { result } = renderCeremony();
    const res = await result.current.status();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [input, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(input)).toBe("https://platform.test/api/v1/ceremony/status");
    expect(init?.method ?? "GET").toBe("GET");
    expect(res.data?.state).toBe("CEREMONY_STATE_IN_PROGRESS");
  });

  it("init posts its request body to /api/v1/ceremony/init", async () => {
    fetchMock.mockImplementation(() =>
      Promise.resolve(ok({ ceremonyId: "c-1", state: "CEREMONY_STATE_IN_PROGRESS" }))
    );
    const request = { soPin: "1234", userPin: "5678", threshold: "3-of-5", sans: ["ca.test"] };
    const { result } = renderCeremony();
    await result.current.init(request);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [input, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(input)).toBe("https://platform.test/api/v1/ceremony/init");
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual(request);
  });

  it("the hook returns the same object across renders on one client", () => {
    const { result, rerender } = renderCeremony();
    const first = result.current;
    rerender();
    expect(result.current).toBe(first);
  });

  it("the barrel exports useCeremony", () => {
    expect(hooks.useCeremony).toBe(useCeremony);
  });
});
