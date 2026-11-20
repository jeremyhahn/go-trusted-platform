import * as React from "react";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2023 Codex round 1: TenantGRPCServer.Sync reports a failed run in
// status.success=false inside an HTTP 200 response, so the page must read the
// in-band status rather than the SDK's outer success flag.

const syncTenants = vi.fn();

vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "t-1" }),
  usePathname: () => "/admin/tenants/t-1/",
}));

const tenantSvc = vi.hoisted(() => ({
  suspendTenant: vi.fn(),
  rotateDEK: vi.fn(),
  sealBarrier: vi.fn(),
  updateQuotas: vi.fn(),
}));

const apiResult = vi.hoisted(() => ({
  data: {
    tenant: {
      tenantId: "t-1",
      name: "Acme",
      state: "ACTIVE",
      computeQuota: { maxVms: 4, maxContainers: 7, maxVcpus: 8, maxMemoryMb: 1024 },
    },
  },
  isLoading: false,
  error: null,
  refetch: () => Promise.resolve(),
}));

// The barrier suite below runs the page against the real SDK tenant
// service (only fetch is stubbed); the other suites use the mocked service.
const realSdk = vi.hoisted(() => ({ on: false }));

vi.mock("@/hooks", async () => {
  const sdk = await vi.importActual<typeof import("trusted-platform-sdk")>("trusted-platform-sdk");
  return {
    useApi: () => apiResult,
    useTenant: () => (realSdk.on ? sdk.useTenant() : { syncTenants, ...tenantSvc }),
  };
});

import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";
import TenantDetailClient from "./tenant-detail-client";

async function clickSync() {
  render(<TenantDetailClient />);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: "Sync tenants" }));
  });
}

describe("TenantDetailClient sync", () => {
  beforeEach(() => syncTenants.mockReset());
  afterEach(() => cleanup());

  it("shows the in-band failure message when the sync run fails", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: false, message: "sync backend down" } },
    });
    await clickSync();
    const result = screen.getByTestId("action-result");
    expect(result.textContent).toContain("sync backend down");
    expect(result.textContent).not.toContain("Tenants synced");
  });

  it("reports success when the sync run succeeds", async () => {
    syncTenants.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" } },
    });
    await clickSync();
    expect(screen.getByTestId("action-result").textContent).toBe("Tenants synced");
  });
});

// #2023 Codex round 2: the destructive actions ask first, Cancel sends
// nothing, Confirm sends one request for this page's tenant, and a refusal
// shows its message. A quota save keeps the limits that were not edited.
describe("TenantDetailClient actions", () => {
  beforeEach(() => {
    for (const fn of Object.values(tenantSvc)) fn.mockReset();
  });
  afterEach(() => cleanup());

  const refusal = { success: false, error: { message: "refused by policy" } };

  const confirmed = [
    {
      name: "suspend",
      open: "Suspend",
      call: () => tenantSvc.suspendTenant,
      args: ["t-1"],
      ok: { success: true, data: {} },
      done: "Tenant suspended",
    },
    {
      name: "DEK rotation",
      open: "Rotate DEK",
      call: () => tenantSvc.rotateDEK,
      args: [{ tenantId: "t-1" }],
      ok: { success: true, data: { oldVersion: 1, newVersion: 2 } },
      done: "DEK rotated from version 1 to 2",
    },
    {
      name: "barrier seal",
      open: "Seal barrier",
      call: () => tenantSvc.sealBarrier,
      args: ["t-1"],
      ok: { success: true, data: {} },
      done: "Barrier sealed",
    },
  ];

  async function open(label: string) {
    render(<TenantDetailClient />);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: label }));
    });
    expect(screen.getByTestId("confirm-dialog")).toBeTruthy();
  }

  it.each(confirmed)("sends no $name request when Cancel is chosen", async ({ open: label, call }) => {
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    });
    expect(screen.queryByTestId("confirm-dialog")).toBeNull();
    expect(call()).not.toHaveBeenCalled();
  });

  it.each(confirmed)("sends one $name request for this tenant on Confirm", async ({ open: label, call, args, ok, done }) => {
    call().mockResolvedValue(ok);
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-action"));
    });
    expect(call()).toHaveBeenCalledTimes(1);
    expect(call()).toHaveBeenCalledWith(...args);
    expect(screen.getByTestId("action-result").textContent).toBe(done);
  });

  it.each(confirmed)("shows the refusal message of a $name", async ({ open: label, call, done }) => {
    call().mockResolvedValue(refusal);
    await open(label);
    await act(async () => {
      fireEvent.click(screen.getByTestId("confirm-action"));
    });
    const result = screen.getByTestId("action-result").textContent;
    expect(result).toBe("refused by policy");
    expect(result).not.toBe(done);
  });

  async function saveQuotas(edits: Record<string, string>) {
    render(<TenantDetailClient />);
    for (const [label, value] of Object.entries(edits)) {
      fireEvent.change(screen.getByLabelText(label), { target: { value } });
    }
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Save quotas" }));
    });
  }

  it("keeps the other compute limits when one limit is edited", async () => {
    tenantSvc.updateQuotas.mockResolvedValue({ success: true, data: {} });
    await saveQuotas({ "Max vCPUs": "16" });
    expect(tenantSvc.updateQuotas).toHaveBeenCalledTimes(1);
    expect(tenantSvc.updateQuotas).toHaveBeenCalledWith({
      tenantId: "t-1",
      compute: { maxVms: 4, maxContainers: 7, maxVcpus: 16, maxMemoryMb: 1024 },
    });
    expect(screen.getByTestId("action-result").textContent).toBe("Quotas updated");
  });

  it("shows the refusal message of a quota update and keeps the edit", async () => {
    tenantSvc.updateQuotas.mockResolvedValue(refusal);
    await saveQuotas({ "Max VMs": "2" });
    expect(tenantSvc.updateQuotas).toHaveBeenCalledWith({
      tenantId: "t-1",
      compute: { maxVms: 2, maxContainers: 7, maxVcpus: 8, maxMemoryMb: 1024 },
    });
    expect(screen.getByTestId("action-result").textContent).toBe("refused by policy");
    expect((screen.getByLabelText("Max VMs") as HTMLInputElement).value).toBe("2");
  });
});

// #2023 Codex round 5: barrier init and unseal change access to the
// tenant's encrypted data. These cases run the page against the real SDK
// tenant service with only fetch stubbed: the request names this page's
// tenant, unseal sends the base64 key, a refusal shows its message and keeps
// the key, and the key field is cleared only after a success.
describe("TenantDetailClient barrier through the SDK", () => {
  interface Sent {
    method: string;
    url: string;
    body: unknown;
  }
  const fetchMock = vi.fn<typeof fetch>();
  let sent: Sent[] = [];
  let reply: (url: string) => Response;

  function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }

  beforeEach(() => {
    realSdk.on = true;
    sent = [];
    fetchMock.mockReset();
    fetchMock.mockImplementation(async (input, init) => {
      const req = input instanceof Request ? input : null;
      const url = req ? req.url : String(input);
      const method = init?.method ?? req?.method ?? "GET";
      const raw = init?.body ?? (req ? await req.clone().text() : undefined);
      sent.push({ method, url, body: typeof raw === "string" && raw ? JSON.parse(raw) : raw });
      return reply(url);
    });
  });
  afterEach(() => {
    cleanup();
    realSdk.on = false;
  });

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    render(
      <PlatformProvider client={client}>
        <TenantDetailClient />
      </PlatformProvider>
    );
  }

  const barrierCalls = () => sent.filter((s) => s.url.includes("/barrier/"));
  const keyField = () => screen.getByLabelText("Unseal key (base64)") as HTMLInputElement;

  async function click(name: string) {
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name }));
    });
  }

  it("initialises the barrier of this page's tenant", async () => {
    reply = () => json(200, { code: 200, error: "", success: true, payload: {} });
    renderPage();
    await click("Initialise barrier");
    const calls = barrierCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toContain("/v1/tenants/t-1/barrier/init");
    expect(screen.getByTestId("action-result").textContent).toBe("Barrier initialised");
  });

  it("shows the refusal of a barrier init", async () => {
    reply = () => json(409, { code: 409, error: "barrier already initialised", success: false });
    renderPage();
    await click("Initialise barrier");
    expect(barrierCalls()).toHaveLength(1);
    const result = screen.getByTestId("action-result").textContent;
    expect(result).toContain("barrier already initialised");
    expect(result).not.toBe("Barrier initialised");
  });

  it("unseals this page's tenant with the base64 key and clears the key after success", async () => {
    reply = () => json(200, { code: 200, error: "", success: true, payload: {} });
    renderPage();
    fireEvent.change(keyField(), { target: { value: "a2V5LW1hdGVyaWFs" } });
    await click("Unseal barrier");
    const calls = barrierCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("POST");
    expect(calls[0].url).toContain("/v1/tenants/t-1/barrier/unseal");
    expect(calls[0].body).toEqual({ key: "a2V5LW1hdGVyaWFs" });
    expect(screen.getByTestId("action-result").textContent).toBe("Barrier unsealed");
    expect(keyField().value).toBe("");
  });

  it("shows the refusal of an unseal and keeps the key", async () => {
    reply = () => json(403, { code: 403, error: "unseal refused by policy", success: false });
    renderPage();
    fireEvent.change(keyField(), { target: { value: "a2V5LW1hdGVyaWFs" } });
    await click("Unseal barrier");
    const calls = barrierCalls();
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toEqual({ key: "a2V5LW1hdGVyaWFs" });
    const result = screen.getByTestId("action-result").textContent;
    expect(result).toContain("unseal refused by policy");
    expect(result).not.toBe("Barrier unsealed");
    expect(keyField().value).toBe("a2V5LW1hdGVyaWFs");
  });
});
