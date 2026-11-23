import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the dashboard reads users, devices, certificates, health,
// metrics and the tenant through the service hooks (network boundary, mocked
// here) and runs each read only when the server offers its route.

const { iam, device, ca, platform, tenant, caps, capability } = vi.hoisted(() => ({
  iam: { listUsers: vi.fn() },
  device: { listDevices: vi.fn() },
  ca: { listCertificates: vi.fn() },
  platform: { getHealth: vi.fn(), getMetrics: vi.fn() },
  tenant: { getTenant: vi.fn() },
  caps: { loading: false },
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useIAM: () => iam,
  useDevice: () => device,
  useCA: () => ca,
  usePlatform: () => platform,
  useTenant: () => tenant,
}));

vi.mock("@/contexts/AuthContext", () => ({ useAuth: () => ({ tenantId: "t-1" }) }));

// #2033 item 5: the page reads the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

import DashboardPage from "./page";

const USERS_OP = "GET /api/v1/iam/tenants/{tenant}/users";
const DEVICES_OP = "GET /api/v1/devices";
const CERTS_OP = "GET /api/v1/ca/certificates";
const HEALTH_OP = "GET /api/v1/platform/health";
const METRICS_OP = "GET /api/v1/platform/metrics";
const TENANT_OP = "GET /api/v1/tenants/{id}";
const ALL_OPS = [USERS_OP, DEVICES_OP, CERTS_OP, HEALTH_OP, METRICS_OP, TENANT_OP];
const REASON = "blocked: integration";

const STAT_IDS = [
  "dashboard-stat-total-users",
  "dashboard-stat-active-devices",
  "dashboard-stat-certificates",
  "dashboard-stat-platform-health",
  "dashboard-stat-services",
  "dashboard-stat-network",
];

const reads = () => ({
  [USERS_OP]: iam.listUsers,
  [DEVICES_OP]: device.listDevices,
  [CERTS_OP]: ca.listCertificates,
  [HEALTH_OP]: platform.getHealth,
  [METRICS_OP]: platform.getMetrics,
  [TENANT_OP]: tenant.getTenant,
});

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
}

async function expectOnlyOffWithheld(off: string[]) {
  const all = reads();
  await waitFor(() => {
    for (const op of ALL_OPS) {
      if (!off.includes(op)) expect(all[op]).toHaveBeenCalled();
    }
  });
  for (const op of off) expect(all[op]).not.toHaveBeenCalled();
}

function card(id: string): HTMLElement {
  return screen.getByTestId(id);
}

beforeEach(() => {
  iam.listUsers.mockReset().mockResolvedValue({ success: true, data: { users: [], total: 3 } });
  device.listDevices.mockReset().mockResolvedValue({ success: true, data: { devices: [], pagination: { totalItems: 2 } } });
  ca.listCertificates.mockReset().mockResolvedValue({ success: true, data: { certificates: [], pagination: { totalItems: 5 } } });
  platform.getHealth.mockReset().mockResolvedValue({
    success: true,
    data: { health: { healthy: true, message: "ok", services: [] } },
  });
  platform.getMetrics.mockReset().mockResolvedValue({
    success: true,
    data: { metrics: { cpuUsagePercent: 10, memoryUsagePercent: 20, diskUsagePercent: 30 } },
  });
  tenant.getTenant.mockReset().mockResolvedValue({
    success: true,
    data: { tenant: { id: "t-1", name: "Acme", state: "ACTIVE" } },
  });
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("DashboardPage capability gate", () => {
  it("shows the reason on Total Users and does not list users when GET /api/v1/iam/tenants/{tenant}/users is not offered", async () => {
    offExcept([USERS_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([USERS_OP]);
    await waitFor(() => expect(card("dashboard-stat-total-users").textContent).toContain(REASON));
  });

  it("shows the reason on Active Devices and does not list devices when GET /api/v1/devices is not offered", async () => {
    offExcept([DEVICES_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([DEVICES_OP]);
    await waitFor(() => expect(card("dashboard-stat-active-devices").textContent).toContain(REASON));
  });

  it("shows the reason on Certificates and does not list certificates when GET /api/v1/ca/certificates is not offered", async () => {
    offExcept([CERTS_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([CERTS_OP]);
    await waitFor(() => expect(card("dashboard-stat-certificates").textContent).toContain(REASON));
  });

  it("shows the reason on Platform Health, Services and Network when GET /api/v1/platform/health is not offered", async () => {
    offExcept([HEALTH_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([HEALTH_OP]);
    await waitFor(() => {
      for (const id of ["dashboard-stat-platform-health", "dashboard-stat-services", "dashboard-stat-network"]) {
        expect(card(id).textContent).toContain(REASON);
      }
    });
  });

  it("shows the not-enabled System Health panel when GET /api/v1/platform/metrics is not offered", async () => {
    offExcept([METRICS_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([METRICS_OP]);
    const panel = await screen.findByTestId("dashboard-metrics-not-enabled");
    expect(panel.textContent).toContain(REASON);
    expect(screen.queryByText("Unable to load system metrics")).toBeNull();
  });

  it("shows the not-enabled Tenant Information card when GET /api/v1/tenants/{id} is not offered", async () => {
    offExcept([TENANT_OP]);
    render(<DashboardPage />);

    await expectOnlyOffWithheld([TENANT_OP]);
    const tenantCard = await screen.findByTestId("dashboard-tenant-not-enabled");
    expect(tenantCard.textContent).toContain(REASON);
  });

  it("never raises the error alert for a read that is not offered", async () => {
    for (const fn of Object.values(reads())) fn.mockRejectedValue(new Error("boom"));
    offExcept(ALL_OPS);
    render(<DashboardPage />);

    await waitFor(() => expect(card("dashboard-stat-total-users").textContent).toContain(REASON));
    for (const fn of Object.values(reads())) expect(fn).not.toHaveBeenCalled();
    expect(screen.queryByText("Error loading data")).toBeNull();
  });

  it("waits for the capabilities before any read and shows no not-enabled state while they load", async () => {
    caps.loading = true;
    offExcept(ALL_OPS);
    render(<DashboardPage />);

    for (const id of STAT_IDS) expect(card(id).textContent).toContain("Loading...");
    for (const fn of Object.values(reads())) expect(fn).not.toHaveBeenCalled();
    expect(screen.queryByText(REASON)).toBeNull();
    expect(screen.queryByTestId("dashboard-metrics-not-enabled")).toBeNull();
    expect(screen.queryByTestId("dashboard-tenant-not-enabled")).toBeNull();
  });

  it("withholds Refresh with the server's reason when no read is offered", async () => {
    offExcept(ALL_OPS);
    render(<DashboardPage />);

    await waitFor(() => expect(card("dashboard-stat-network").textContent).toContain(REASON));
    expectWithheld(button("Refresh"));
  });

  it("runs every read and leaves Refresh enabled when the server offers every route", async () => {
    render(<DashboardPage />);

    const all = reads();
    await waitFor(() => {
      for (const op of ALL_OPS) expect(all[op]).toHaveBeenCalledTimes(1);
    });
    for (const op of ALL_OPS) expect(capability).toHaveBeenCalledWith(op);
    await waitFor(() => expect(card("dashboard-stat-total-users").textContent).toContain("3"));
    expect(screen.queryByText(REASON)).toBeNull();
    expect(screen.queryByTestId("dashboard-metrics-not-enabled")).toBeNull();
    expect(screen.queryByTestId("dashboard-tenant-not-enabled")).toBeNull();

    const refresh = button("Refresh");
    expect(refresh.disabled).toBe(false);
    fireEvent.click(refresh);
    await waitFor(() => {
      for (const op of [USERS_OP, DEVICES_OP, CERTS_OP, HEALTH_OP, METRICS_OP]) expect(all[op]).toHaveBeenCalledTimes(2);
    });
  });
});
