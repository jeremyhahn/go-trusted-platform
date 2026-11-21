import type { ReactNode } from "react";
import { cleanup, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import { useNTP } from "./use-ntp";

// #2058: the NTP hook calls the SDK's NTPService on `client.ntp`, not a
// hand-written fetch around it.

const status = {
  synced: true,
  stratum: 2,
  leapStatus: "normal",
  offsetSeconds: 0.0001,
  rootDispersion: 0.001,
  rootDelay: 0.002,
  lastSyncUnix: "1760300000",
  mode: "client",
  referenceId: "C0A80001",
  referenceName: "ntp.test",
  sourcesReachable: 1,
  sourcesTotal: 1,
  anomaly: false,
  anomalyReason: "",
};

const source = {
  address: "ntp.test",
  mode: "server",
  state: "selected",
  stratum: 1,
  pollSeconds: 64,
  reach: 255,
  lastRxSeconds: "12",
  offsetSeconds: 0.0001,
  reachable: true,
};

describe("useNTP", () => {
  const fetchMock = vi.fn<typeof fetch>();
  let client: PlatformClient;

  function render() {
    const wrapper = ({ children }: { children: ReactNode }) => (
      <PlatformProvider client={client}>{children}</PlatformProvider>
    );
    return renderHook(() => useNTP(), { wrapper }).result.current;
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
    cleanup();
    vi.restoreAllMocks();
  });

  it("getStatus calls client.ntp.getStatus", async () => {
    const spy = vi
      .spyOn(client.ntp, "getStatus")
      .mockResolvedValue({ success: true, data: { status } } as never);

    const res = await render().getStatus();

    expect(spy).toHaveBeenCalledTimes(1);
    expect(res.data?.status.referenceName).toBe("ntp.test");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("listSources calls client.ntp.listSources", async () => {
    const spy = vi
      .spyOn(client.ntp, "listSources")
      .mockResolvedValue({ success: true, data: { sources: [source] } } as never);

    const res = await render().listSources();

    expect(spy).toHaveBeenCalledTimes(1);
    expect(res.data?.sources[0]?.address).toBe("ntp.test");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("step calls client.ntp.step", async () => {
    const spy = vi
      .spyOn(client.ntp, "step")
      .mockResolvedValue({ success: true, data: { status } } as never);

    const res = await render().step();

    expect(spy).toHaveBeenCalledTimes(1);
    expect(res.data?.status.synced).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
