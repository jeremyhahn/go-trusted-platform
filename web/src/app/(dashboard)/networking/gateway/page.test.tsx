import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SERVICE_NOT_CONFIGURED } from "trusted-platform-sdk";

// #1844: the page reads the reported-gateways telemetry (useReportedGateways)
// and four local gateway endpoints through useGateway; both network
// boundaries are mocked here.

type Reported = {
  gateways: Array<Record<string, unknown>>;
  isLoading: boolean;
  error: string | null;
  refetch: ReturnType<typeof vi.fn>;
};

const { gateway, toast, reported } = vi.hoisted(() => ({
  gateway: {
    getStatus: vi.fn(),
    getBGPStatus: vi.fn(),
    listAnnouncedPrefixes: vi.fn(),
    listIPAMPools: vi.fn(),
  },
  toast: vi.fn(),
  reported: { current: undefined as unknown as Reported },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useGateway: () => gateway,
  useToast: () => ({ toast }),
  useReportedGateways: () => reported.current,
}));

vi.mock("@/components/features/networking/gateway-snapshot-detail", () => ({
  GatewaySnapshotDetail: ({ snapshot }: { snapshot: { gateway_id: string } }) => (
    <div data-testid="snapshot-detail">{snapshot.gateway_id}</div>
  ),
}));

import APIGatewayPage from "./page";

const notConfigured = { error: { status: 503, message: "gateway not configured", details: { reason: SERVICE_NOT_CONFIGURED } } };

function allOk() {
  gateway.getStatus.mockResolvedValue({ data: { status: { healthy: true, uptimeSeconds: 7300 } } });
  gateway.getBGPStatus.mockResolvedValue({
    data: { status: { establishedPeers: 2, peerCount: 3, localAsn: 65001, routerId: "192.0.2.1", prefixesAnnounced: 4 } },
  });
  gateway.listAnnouncedPrefixes.mockResolvedValue({
    data: {
      prefixes: [
        { prefix: "198.51.100.0/24", nextHop: "192.0.2.1", announcedAt: "2026-11-01T00:00:00Z" },
        { prefix: "203.0.113.0/24", nextHop: "192.0.2.2" },
      ],
    },
  });
  gateway.listIPAMPools.mockResolvedValue({ data: { pools: [{ id: "pool-a", cidr: "10.0.0.0/24", available: 200 }, { id: "pool-b", cidr: "10.1.0.0/24" }] } });
}

function allEmpty() {
  gateway.getStatus.mockResolvedValue({ data: {} });
  gateway.getBGPStatus.mockResolvedValue({ data: {} });
  gateway.listAnnouncedPrefixes.mockResolvedValue({ data: {} });
  gateway.listIPAMPools.mockResolvedValue({ data: {} });
}

function statValue(label: string): string {
  const card = screen.getAllByText(label)[0].closest("div.rounded-lg") as HTMLElement;
  return (card.lastElementChild as HTMLElement).textContent ?? "";
}

beforeEach(() => {
  for (const fn of Object.values(gateway)) fn.mockReset();
  toast.mockReset();
  reported.current = { gateways: [], isLoading: false, error: null, refetch: vi.fn().mockResolvedValue(undefined) };
});

afterEach(() => {
  cleanup();
});

describe("APIGatewayPage", () => {
  it("renders status, BGP, prefixes and pools from the local gateway", async () => {
    allOk();
    render(<APIGatewayPage />);

    expect(await screen.findByText("198.51.100.0/24")).toBeTruthy();
    expect(screen.getByText("Healthy")).toBeTruthy();
    expect(statValue("Uptime")).toBe("2h");
    expect(statValue("BGP Peers")).toBe("2 / 3");
    expect(screen.getByText("pool-a")).toBeTruthy();
    expect(screen.getByText("200")).toBeTruthy();
    // A pool with no available count shows 0; a prefix with no time shows "-".
    expect(screen.getByText("0")).toBeTruthy();
    expect(screen.getByText("-")).toBeTruthy();
    expect(screen.getByText("BGP Status")).toBeTruthy();
    expect(screen.getByText("65001")).toBeTruthy();
    expect(toast).not.toHaveBeenCalled();
  });

  it("shows only the first five prefixes and pools", async () => {
    allOk();
    gateway.listAnnouncedPrefixes.mockResolvedValue({
      data: { prefixes: Array.from({ length: 7 }, (_, i) => ({ prefix: `10.${i}.0.0/16`, nextHop: "192.0.2.9" })) },
    });
    gateway.listIPAMPools.mockResolvedValue({
      data: { pools: Array.from({ length: 6 }, (_, i) => ({ id: `p-${i}`, cidr: `10.${i}.0.0/24`, available: 1 })) },
    });
    render(<APIGatewayPage />);

    expect(await screen.findByText("10.4.0.0/16")).toBeTruthy();
    expect(screen.queryByText("10.5.0.0/16")).toBeNull();
    expect(screen.getByText("p-4")).toBeTruthy();
    expect(screen.queryByText("p-5")).toBeNull();
    expect(statValue("IPAM Pools")).toBe("6");
  });

  it("renders the empty states with no local data", async () => {
    allEmpty();
    render(<APIGatewayPage />);

    expect(await screen.findByText("No announced prefixes")).toBeTruthy();
    expect(screen.getByText("No IPAM pools configured")).toBeTruthy();
    expect(screen.getByText("Unhealthy")).toBeTruthy();
    expect(statValue("Uptime")).toBe("0h");
    expect(statValue("BGP Peers")).toBe("0 / 0");
    expect(screen.queryByText("BGP Status")).toBeNull();
    expect(screen.getByText(/No gatewayd processes have reported yet/)).toBeTruthy();
    expect(screen.queryByTestId("snapshot-detail")).toBeNull();
  });

  it("renders the informational state without toasts when every endpoint is not configured", async () => {
    gateway.getStatus.mockResolvedValue(notConfigured);
    gateway.getBGPStatus.mockResolvedValue(notConfigured);
    gateway.listAnnouncedPrefixes.mockResolvedValue(notConfigured);
    gateway.listIPAMPools.mockResolvedValue(notConfigured);
    render(<APIGatewayPage />);

    expect(await screen.findByText(/This node does not run gatewayd/)).toBeTruthy();
    expect(screen.queryByText("Error loading local gateway service")).toBeNull();
    expect(screen.queryByText("BGP Peers")).toBeNull();
    expect(toast).not.toHaveBeenCalled();
  });

  it("shows the local error and toasts a real failure next to not-configured endpoints", async () => {
    gateway.getStatus.mockResolvedValue({ error: { status: 500, message: "status broke" } });
    gateway.getBGPStatus.mockResolvedValue(notConfigured);
    gateway.listAnnouncedPrefixes.mockResolvedValue(notConfigured);
    gateway.listIPAMPools.mockResolvedValue(notConfigured);
    render(<APIGatewayPage />);

    expect(await screen.findByText("Error loading local gateway service")).toBeTruthy();
    expect(screen.getByText("status broke")).toBeTruthy();
    await waitFor(() =>
      expect(toast).toHaveBeenCalledWith({
        title: "Error loading gateway status",
        description: "status broke",
        variant: "destructive",
      }),
    );
    expect(toast).toHaveBeenCalledTimes(1);
    expect(screen.queryByText(/This node does not run gatewayd/)).toBeNull();
  });

  it("toasts each failing endpoint with its own title", async () => {
    gateway.getStatus.mockResolvedValue({ error: { status: 500, message: "a" } });
    gateway.getBGPStatus.mockResolvedValue({ error: { status: 500, message: "b" } });
    gateway.listAnnouncedPrefixes.mockResolvedValue({ error: { status: 500, message: "c" } });
    gateway.listIPAMPools.mockResolvedValue({ error: { status: 503, message: "d" } });
    render(<APIGatewayPage />);

    await waitFor(() => expect(toast).toHaveBeenCalledTimes(4));
    const titles = toast.mock.calls.map((c) => (c[0] as { title: string }).title).sort();
    expect(titles).toEqual([
      "Error loading BGP status",
      "Error loading IPAM pools",
      "Error loading announced prefixes",
      "Error loading gateway status",
    ]);
    // A 503 without the not-configured reason is a real error.
    expect(screen.getByText("Error loading local gateway service")).toBeTruthy();
  });

  it("lists reported gateways and details the first by default", async () => {
    allEmpty();
    reported.current.gateways = [
      {
        gateway_id: "gw-1",
        hostname: "edge-1",
        mode: "router",
        health: { status: "healthy" },
        bgp: { established_peers: 1, peer_count: 2 },
        reported_at: "2026-11-01T00:00:00Z",
      },
      { gateway_id: "gw-2", reported_at: "2026-11-01T00:00:00Z" },
    ];
    render(<APIGatewayPage />);

    expect(screen.getByText("edge-1")).toBeTruthy();
    expect(screen.getByText("healthy")).toBeTruthy();
    expect(screen.getByText("unknown")).toBeTruthy();
    expect(screen.getAllByText("—")).toHaveLength(2);
    expect(screen.getByTestId("snapshot-detail").textContent).toBe("gw-1");

    fireEvent.click(screen.getByText("gw-2"));
    expect(screen.getByTestId("snapshot-detail").textContent).toBe("gw-2");
  });

  it("shows the loading line while the first reported-gateways read is in flight", () => {
    allEmpty();
    reported.current.isLoading = true;
    render(<APIGatewayPage />);

    expect(screen.getByText("Loading reported gateways…")).toBeTruthy();
  });

  it("shows the reported-gateways error", () => {
    allEmpty();
    reported.current.error = "telemetry unavailable";
    render(<APIGatewayPage />);

    expect(screen.getByText("Failed to load: telemetry unavailable")).toBeTruthy();
  });

  it("refreshes every source from the refresh button", async () => {
    allEmpty();
    render(<APIGatewayPage />);
    await screen.findByText("No announced prefixes");

    const refresh = screen.getAllByRole("button")[0];
    fireEvent.click(refresh);

    expect(reported.current.refetch).toHaveBeenCalledTimes(1);
    await waitFor(() => {
      expect(gateway.getStatus).toHaveBeenCalledTimes(2);
      expect(gateway.getBGPStatus).toHaveBeenCalledTimes(2);
      expect(gateway.listAnnouncedPrefixes).toHaveBeenCalledTimes(2);
      expect(gateway.listIPAMPools).toHaveBeenCalledTimes(2);
    });
  });
});
