import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiClient, GatewayService } from "trusted-platform-sdk";

import { GatewayVIPsCard, parseBackends } from "./gateway-vips-card";

// #2052: the card drives the load-balancer routes (GET/POST /lb/vips,
// DELETE /lb/vips/{p}/{a}/{port}, PUT .../backends) through the real SDK
// GatewayService; only fetch and the session are stubbed.

const fetchMock = vi.fn<typeof fetch>();
const gatewayService = new GatewayService(
  new ApiClient({ baseUrl: "https://platform.test/api", fetch: fetchMock, retry: { maxRetries: 0 } })
);
const auth: { current: { user: { roles: string[] } } } = { current: { user: { roles: ["admin"] } } };

vi.mock("@/hooks", () => ({
  useGateway: () => gatewayService,
  useOptionalAuth: () => auth.current,
}));

// The card's writes sit in <Gated>; the ops listed here are the ones the
// server does not offer, with their reason.
const capsOff: { current: Record<string, string> } = { current: {} };

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      op in capsOff.current ? { enabled: false, reason: capsOff.current[op] } : { enabled: true },
  }),
}));

const ADD_OP = "POST /api/v1/gateway/lb/vips";
const BACKENDS_OP = "PUT /api/v1/gateway/lb/vips/{protocol}/{address}/{port}/backends";
const REMOVE_OP = "DELETE /api/v1/gateway/lb/vips/{protocol}/{address}/{port}";
const GET_OP = "GET /api/v1/gateway/lb/vips/{protocol}/{address}/{port}";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const LIST_URL = "https://platform.test/api/v1/gateway/lb/vips";
const VIP_URL = "https://platform.test/api/v1/gateway/lb/vips/tcp/192.0.2.10/443";
const KEY = "tcp-192.0.2.10-443";

const listedVIP = {
  vip: {
    address: "192.0.2.10",
    port: 443,
    protocol: "tcp",
    algorithm: "hash",
    backends: [
      { address: "192.0.2.21", port: 8443, weight: 0 },
      { address: "192.0.2.22", port: 8443, weight: 0 },
    ],
  },
  ctZone: 7,
  groupId: 3,
  backends: [
    { backend: { address: "192.0.2.21", port: 8443, weight: 0 }, healthy: true },
    { backend: { address: "192.0.2.22", port: 8443, weight: 0 }, healthy: false },
  ],
};

let vips: unknown[] = [listedVIP];
let writeAnswer: (() => Response) | null = null;

function methodOf(init: RequestInit | undefined): string {
  return (init?.method ?? "GET").toUpperCase();
}

function calls(method: string, url: string) {
  return fetchMock.mock.calls.filter(
    ([u, init]) => methodOf(init as RequestInit | undefined) === method && String(u) === url
  );
}

function writeCalls() {
  return fetchMock.mock.calls.filter(([, init]) => methodOf(init as RequestInit | undefined) !== "GET");
}

function bodyOf(call: unknown[]): unknown {
  return JSON.parse(String((call[1] as RequestInit).body));
}

async function renderCard() {
  render(<GatewayVIPsCard />);
  await waitFor(() => expect(calls("GET", LIST_URL).length).toBe(1));
}

async function click(testId: string) {
  await act(async () => screen.getByTestId(testId).click());
}

describe("GatewayVIPsCard", () => {
  beforeEach(() => {
    fetchMock.mockReset();
    auth.current = { user: { roles: ["admin"] } };
    vips = [listedVIP];
    writeAnswer = null;
    capsOff.current = {};
    fetchMock.mockImplementation(async (url, init) => {
      if (methodOf(init) === "GET" && String(url) === LIST_URL) {
        return jsonResponse(200, { code: 200, success: true, payload: { vips } });
      }
      if (writeAnswer) {
        return writeAnswer();
      }
      return jsonResponse(200, { code: 200, success: true, payload: { status: null, vip: null } });
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("lists the VIPs", async () => {
    await renderCard();

    const row = await screen.findByTestId(`vip-${KEY}`);
    const text = row.textContent ?? "";
    expect(text).toContain("tcp 192.0.2.10:443");
    expect(text).toContain("hash");
    expect(text).toContain("1/2 backends healthy");
  });

  it("an empty list says so", async () => {
    vips = [];
    await renderCard();

    expect((await screen.findByTestId("vips-empty")).textContent).toBe("No VIPs configured.");
  });

  it("a non-admin sees the writes disabled with the reason", async () => {
    auth.current = { user: { roles: ["user"] } };
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    expect((screen.getByTestId("vip-add") as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByTestId(`vip-remove-${KEY}`) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByTestId(`vip-edit-${KEY}`) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId("vips-admin-only").textContent).toBe(
      "Requires the admin role: VIP changes reprogram the gateway's switch."
    );
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(writeCalls()).toHaveLength(0);
  });

  it("adds a VIP and re-reads the list", async () => {
    await renderCard();

    fireEvent.change(screen.getByTestId("vip-protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByTestId("vip-address"), { target: { value: "192.0.2.11" } });
    fireEvent.change(screen.getByTestId("vip-port"), { target: { value: "80" } });
    fireEvent.change(screen.getByTestId("vip-backends"), {
      target: { value: "192.0.2.21:8080\n192.0.2.22:8080 3" },
    });
    await click("vip-add");

    await waitFor(() => expect(calls("GET", LIST_URL).length).toBe(2));
    const posts = calls("POST", LIST_URL);
    expect(posts).toHaveLength(1);
    expect(bodyOf(posts[0])).toEqual({
      vip: {
        protocol: "tcp",
        address: "192.0.2.11",
        port: 80,
        algorithm: "",
        backends: [
          { address: "192.0.2.21", port: 8080, weight: 0 },
          { address: "192.0.2.22", port: 8080, weight: 3 },
        ],
      },
    });
  });

  it("a bad backend line sends nothing", async () => {
    await renderCard();

    fireEvent.change(screen.getByTestId("vip-address"), { target: { value: "192.0.2.11" } });
    fireEvent.change(screen.getByTestId("vip-port"), { target: { value: "80" } });
    fireEvent.change(screen.getByTestId("vip-backends"), { target: { value: "192.0.2.21" } });
    await click("vip-add");

    expect(screen.getByTestId("vip-form-error").textContent).toBe("Line 1: expected address:port [weight]");
    expect(writeCalls()).toHaveLength(0);
  });

  it("replaces the backends", async () => {
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    await click(`vip-edit-${KEY}`);
    const textarea = screen.getByTestId(`vip-edit-backends-${KEY}`) as HTMLTextAreaElement;
    expect(textarea.value).toBe("192.0.2.21:8443\n192.0.2.22:8443");
    fireEvent.change(textarea, { target: { value: "192.0.2.23:8443" } });
    await click(`vip-save-${KEY}`);

    await waitFor(() => expect(calls("GET", LIST_URL).length).toBe(2));
    const puts = calls("PUT", `${VIP_URL}/backends`);
    expect(puts).toHaveLength(1);
    expect(bodyOf(puts[0])).toEqual({ backends: [{ address: "192.0.2.23", port: 8443, weight: 0 }] });
    expect(writeCalls()).toHaveLength(1);
  });

  it("removes only after the confirm", async () => {
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    await click(`vip-remove-${KEY}`);
    expect(calls("DELETE", VIP_URL)).toHaveLength(0);
    const dialog = screen.getByTestId("vip-remove-dialog");
    expect(screen.getByText("Remove this VIP?")).toBeTruthy();
    expect(dialog.textContent ?? "").toContain("2 backends");

    await click("vip-remove-cancel");
    expect(screen.queryByTestId("vip-remove-dialog")).toBeNull();
    expect(calls("DELETE", VIP_URL)).toHaveLength(0);

    await click(`vip-remove-${KEY}`);
    await click("vip-remove-confirm");

    await waitFor(() => expect(calls("GET", LIST_URL).length).toBe(2));
    expect(calls("DELETE", VIP_URL)).toHaveLength(1);
    expect(writeCalls()).toHaveLength(1);
  });

  it("a refused write shows the server message", async () => {
    writeAnswer = () =>
      jsonResponse(409, { code: 409, success: false, error: "lb: vip tcp 192.0.2.11:80 exists" });
    await renderCard();

    fireEvent.change(screen.getByTestId("vip-address"), { target: { value: "192.0.2.11" } });
    fireEvent.change(screen.getByTestId("vip-port"), { target: { value: "80" } });
    fireEvent.change(screen.getByTestId("vip-backends"), { target: { value: "192.0.2.21:8080" } });
    await click("vip-add");

    expect((await screen.findByTestId("vips-error")).textContent).toContain("exists");
    expect((screen.getByTestId("vip-add") as HTMLButtonElement).disabled).toBe(false);
  });

  it("each write carries its capability op", async () => {
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    const expectOp = (testId: string, op: string) => {
      const el = screen.getByTestId(testId);
      expect(el.getAttribute("data-capability-op")).toBe(op);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    };
    expectOp("vip-add", ADD_OP);
    expect((screen.getByTestId("vip-add") as HTMLButtonElement).disabled).toBe(false);
    expectOp(`vip-edit-${KEY}`, BACKENDS_OP);
    expectOp(`vip-remove-${KEY}`, REMOVE_OP);

    await click(`vip-edit-${KEY}`);
    expectOp(`vip-save-${KEY}`, BACKENDS_OP);

    await click(`vip-remove-${KEY}`);
    expectOp("vip-remove-confirm", REMOVE_OP);
  });

  it("an admin sees each write the server does not offer disabled with its reason and sends nothing", async () => {
    const reason = "not-configured: gateway lb";
    capsOff.current = { [ADD_OP]: reason, [BACKENDS_OP]: reason, [REMOVE_OP]: reason };
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    for (const testId of ["vip-add", `vip-edit-${KEY}`, `vip-remove-${KEY}`]) {
      const button = screen.getByTestId(testId) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.title).toBe(reason);
      expect(button.getAttribute("data-capability-enabled")).toBe("false");
    }

    fireEvent.change(screen.getByTestId("vip-address"), { target: { value: "192.0.2.11" } });
    fireEvent.change(screen.getByTestId("vip-port"), { target: { value: "80" } });
    fireEvent.change(screen.getByTestId("vip-backends"), { target: { value: "192.0.2.21:8080" } });
    await click("vip-add");

    expect(writeCalls()).toHaveLength(0);
  });

  it("Details reads the VIP and shows its zone, group and backend health", async () => {
    writeAnswer = () =>
      jsonResponse(200, { code: 200, success: true, payload: { vip: { ...listedVIP, ctZone: 9, groupId: 4 } } });
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    await click(`vip-details-${KEY}`);

    const detail = await screen.findByTestId(`vip-detail-${KEY}`);
    expect(detail.textContent).toContain("ct zone 9");
    expect(detail.textContent).toContain("group 4");
    expect(detail.textContent).toContain("192.0.2.21:8443 healthy");
    expect(detail.textContent).toContain("192.0.2.22:8443 unhealthy");
    expect(calls("GET", VIP_URL)).toHaveLength(1);
    expect(writeCalls()).toHaveLength(0);
  });

  it("a non-admin can read the details", async () => {
    auth.current = { user: { roles: ["user"] } };
    writeAnswer = () =>
      jsonResponse(200, { code: 200, success: true, payload: { vip: { ...listedVIP, ctZone: 9, groupId: 4 } } });
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    expect((screen.getByTestId(`vip-details-${KEY}`) as HTMLButtonElement).disabled).toBe(false);
    await click(`vip-details-${KEY}`);

    await screen.findByTestId(`vip-detail-${KEY}`);
    expect(calls("GET", VIP_URL)).toHaveLength(1);
  });

  it("a refused read shows the server message in the row", async () => {
    writeAnswer = () => jsonResponse(404, { code: 404, error: "vip not found", success: false, payload: null });
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    await click(`vip-details-${KEY}`);

    const err = await screen.findByTestId(`vip-detail-error-${KEY}`);
    expect(err.textContent).toContain("vip not found");
    expect(screen.queryByTestId("vips-error")).toBeNull();
  });

  it("Details the server does not offer is disabled with its reason and reads nothing", async () => {
    capsOff.current = { [GET_OP]: "not-configured: gateway lb" };
    await renderCard();
    await screen.findByTestId(`vip-${KEY}`);

    const button = screen.getByTestId(`vip-details-${KEY}`) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    expect(button.title).toBe("not-configured: gateway lb");
    expect(button.getAttribute("data-capability-op")).toBe(GET_OP);
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    await click(`vip-details-${KEY}`);

    expect(calls("GET", VIP_URL)).toHaveLength(0);
  });

  it("an initial list read that lands after an add's re-read does not restore the old list", async () => {
    let resolveFirst!: (r: Response) => void;
    const first = new Promise<Response>((r) => (resolveFirst = r));
    const addedVIP = {
      vip: {
        address: "192.0.2.11",
        port: 80,
        protocol: "tcp",
        algorithm: "",
        backends: [{ address: "192.0.2.21", port: 8080, weight: 0 }],
      },
      ctZone: 8,
      groupId: 5,
      backends: [{ backend: { address: "192.0.2.21", port: 8080, weight: 0 }, healthy: true }],
    };
    let listReads = 0;
    fetchMock.mockImplementation(async (url, init) => {
      const method = methodOf(init);
      if (method === "GET" && String(url) === LIST_URL) {
        listReads += 1;
        if (listReads === 1) {
          return first;
        }
        return jsonResponse(200, { code: 200, success: true, payload: { vips: [listedVIP, addedVIP] } });
      }
      if (method === "POST" && String(url) === LIST_URL) {
        return jsonResponse(201, { code: 201, success: true, payload: {} });
      }
      return jsonResponse(404, { code: 404, success: false, error: "unexpected" });
    });
    await renderCard();

    fireEvent.change(screen.getByTestId("vip-protocol"), { target: { value: "tcp" } });
    fireEvent.change(screen.getByTestId("vip-address"), { target: { value: "192.0.2.11" } });
    fireEvent.change(screen.getByTestId("vip-port"), { target: { value: "80" } });
    fireEvent.change(screen.getByTestId("vip-backends"), { target: { value: "192.0.2.21:8080" } });
    await click("vip-add");

    await waitFor(() => expect(calls("GET", LIST_URL).length).toBe(2));
    await screen.findByTestId("vip-tcp-192.0.2.11-80");

    await act(async () => {
      resolveFirst(jsonResponse(200, { code: 200, success: true, payload: { vips: [listedVIP] } }));
    });

    expect(screen.getByTestId("vip-tcp-192.0.2.11-80")).toBeTruthy();
    expect(screen.getByTestId(`vip-${KEY}`)).toBeTruthy();
  });
});

describe("parseBackends", () => {
  it("parses address:port with a default weight of 0", () => {
    expect(parseBackends("192.0.2.1:80")).toEqual([{ address: "192.0.2.1", port: 80, weight: 0 }]);
  });

  it("parses an explicit weight", () => {
    expect(parseBackends("192.0.2.1:80 5")).toEqual([{ address: "192.0.2.1", port: 80, weight: 5 }]);
  });

  it("refuses a bad port or a line without one", () => {
    expect(parseBackends("192.0.2.1:0")).toMatch(/^Line 1:/);
    expect(parseBackends("x")).toMatch(/^Line 1:/);
  });

  it("skips blank lines", () => {
    expect(parseBackends("\n192.0.2.1:80\n\n192.0.2.2:81 2\n")).toEqual([
      { address: "192.0.2.1", port: 80, weight: 0 },
      { address: "192.0.2.2", port: 81, weight: 2 },
    ]);
  });
});
