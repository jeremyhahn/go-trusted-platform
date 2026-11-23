import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SERVICE_NOT_CONFIGURED } from "trusted-platform-sdk";

// #2051: the gateway page mounts the BGP peers and announced-prefixes cards
// on a node that runs gatewayd, and neither where it does not.

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
vi.mock("@/components/features/networking/gateway-mode-card", () => ({
  GatewayModeCard: ({ initialModes = [] }: { initialModes?: string[] }) => (
    <div data-testid="gateway-mode-card">{initialModes.join(",")}</div>
  ),
}));
vi.mock("@/components/features/networking/bgp-peers-card", () => ({
  BGPPeersCard: () => <div data-testid="bgp-peers-card" />,
}));
vi.mock("@/components/features/networking/bgp-prefixes-card", () => ({
  BGPPrefixesCard: () => <div data-testid="bgp-prefixes-card" />,
}));

import APIGatewayPage from "./page";

const notConfigured = { error: { status: 503, message: "gateway not configured", details: { reason: SERVICE_NOT_CONFIGURED } } };

function allOk() {
  gateway.getStatus.mockResolvedValue({ data: { status: { healthy: true, uptimeSeconds: 7300 } } });
  gateway.getBGPStatus.mockResolvedValue({
    data: { status: { establishedPeers: 2, peerCount: 3, localAsn: 65001, routerId: "192.0.2.1", prefixesAnnounced: 4 } },
  });
  gateway.listAnnouncedPrefixes.mockResolvedValue({
    data: { prefixes: [{ prefix: "198.51.100.0/24", nextHop: "192.0.2.1", announcedAt: "2026-11-01T00:00:00Z" }] },
  });
  gateway.listIPAMPools.mockResolvedValue({ data: { pools: [] } });
}

beforeEach(() => {
  for (const fn of Object.values(gateway)) fn.mockReset();
  toast.mockReset();
  reported.current = { gateways: [], isLoading: false, error: null, refetch: vi.fn().mockResolvedValue(undefined) };
});

afterEach(() => {
  cleanup();
});

describe("APIGatewayPage BGP cards", () => {
  it("mounts the BGP peers and prefixes cards when the local gateway answers", async () => {
    allOk();
    render(<APIGatewayPage />);

    expect(await screen.findByTestId("bgp-peers-card")).toBeTruthy();
    expect(screen.getByTestId("bgp-prefixes-card")).toBeTruthy();
  });

  it("mounts neither card when the local gateway is not configured", async () => {
    gateway.getStatus.mockResolvedValue(notConfigured);
    gateway.getBGPStatus.mockResolvedValue(notConfigured);
    gateway.listAnnouncedPrefixes.mockResolvedValue(notConfigured);
    gateway.listIPAMPools.mockResolvedValue(notConfigured);
    render(<APIGatewayPage />);

    expect(await screen.findByText(/This node does not run gatewayd/)).toBeTruthy();
    expect(screen.queryByTestId("bgp-peers-card")).toBeNull();
    expect(screen.queryByTestId("bgp-prefixes-card")).toBeNull();
  });
});
