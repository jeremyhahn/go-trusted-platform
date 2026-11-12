import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useReportedGateways, type ReportedGateway } from "./use-reported-gateways";

const fetchMock = vi.fn();

function gw(id: string): ReportedGateway {
  return { gateway_id: id } as unknown as ReportedGateway;
}

function reply(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
  } as unknown as Response;
}

describe("useReportedGateways", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("fetches the gateway state once with the session cookie", async () => {
    fetchMock.mockResolvedValue(reply({ gateways: [gw("a")] }));
    const { result } = renderHook(() => useReportedGateways());
    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith("/api/v1/gateway/state", { credentials: "include" });
    expect(result.current.gateways).toEqual([gw("a")]);
    expect(result.current.error).toBeNull();
  });

  it("reads gateways from an enveloped payload first", async () => {
    fetchMock.mockResolvedValue(reply({ payload: { gateways: [gw("p")] }, gateways: [gw("top")] }));
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.gateways).toEqual([gw("p")]);
  });

  it("falls back to the top-level list when the payload has none", async () => {
    fetchMock.mockResolvedValue(reply({ payload: {}, gateways: [gw("top")] }));
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.gateways).toEqual([gw("top")]);
  });

  it.each([{}, { payload: null }, { gateways: null }])(
    "is an empty list for a body without gateways (%j)",
    async (body) => {
      fetchMock.mockResolvedValue(reply(body));
      const { result } = renderHook(() => useReportedGateways());
      await waitFor(() => expect(result.current.isLoading).toBe(false));
      expect(result.current.gateways).toEqual([]);
      expect(result.current.error).toBeNull();
    }
  );

  it("reports an HTTP failure status as the error", async () => {
    fetchMock.mockResolvedValue(reply({}, 503));
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.error).toBe("HTTP 503");
    expect(result.current.gateways).toEqual([]);
  });

  it("reports a network rejection message", async () => {
    fetchMock.mockRejectedValue(new Error("network down"));
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.error).toBe("network down"));
    expect(result.current.isLoading).toBe(false);
  });

  it("stringifies a non-Error rejection", async () => {
    fetchMock.mockRejectedValue("offline");
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.error).toBe("offline"));
  });

  it("reports a body that is not JSON", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.reject(new SyntaxError("Unexpected token")),
    } as unknown as Response);
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.error).toBe("Unexpected token"));
  });

  it("keeps the last gateways and clears the error on a later success", async () => {
    fetchMock.mockResolvedValueOnce(reply({ gateways: [gw("a")] }));
    const { result } = renderHook(() => useReportedGateways());
    await waitFor(() => expect(result.current.gateways).toEqual([gw("a")]));

    fetchMock.mockResolvedValueOnce(reply({}, 500));
    await act(() => result.current.refetch());
    expect(result.current.error).toBe("HTTP 500");
    expect(result.current.gateways).toEqual([gw("a")]);

    fetchMock.mockResolvedValueOnce(reply({ gateways: [gw("b")] }));
    await act(() => result.current.refetch());
    expect(result.current.error).toBeNull();
    expect(result.current.gateways).toEqual([gw("b")]);
  });

  it("does not fetch and is not loading when disabled", async () => {
    const { result } = renderHook(() => useReportedGateways({ enabled: false }));
    expect(result.current.isLoading).toBe(false);
    await act(() => result.current.refetch());
    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.current.gateways).toEqual([]);
    expect(result.current.error).toBeNull();
  });

  it("starts fetching once it is enabled", async () => {
    fetchMock.mockResolvedValue(reply({ gateways: [gw("late")] }));
    const { result, rerender } = renderHook(
      ({ enabled }) => useReportedGateways({ enabled }),
      { initialProps: { enabled: false } }
    );
    expect(fetchMock).not.toHaveBeenCalled();
    rerender({ enabled: true });
    expect(result.current.isLoading).toBe(true);
    await waitFor(() => expect(result.current.gateways).toEqual([gw("late")]));
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("polls at refreshMs and stops on unmount", async () => {
    vi.useFakeTimers();
    fetchMock.mockResolvedValue(reply({ gateways: [] }));
    const { unmount } = renderHook(() => useReportedGateways({ refreshMs: 1000 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    unmount();
    await vi.advanceTimersByTimeAsync(5000);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("fetches once when refreshMs is 0", async () => {
    vi.useFakeTimers();
    fetchMock.mockResolvedValue(reply({ gateways: [] }));
    renderHook(() => useReportedGateways({ refreshMs: 0 }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not update state from a request that lands after unmount", async () => {
    let resolve: (r: Response) => void = () => undefined;
    fetchMock.mockReturnValue(new Promise<Response>((r) => (resolve = r)));
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { result, unmount } = renderHook(() => useReportedGateways());
    unmount();
    await act(async () => {
      resolve(reply({ gateways: [gw("stale")] }));
      await Promise.resolve();
    });
    expect(result.current.gateways).toEqual([]);
    expect(errorSpy).not.toHaveBeenCalled();
    errorSpy.mockRestore();
  });
});
