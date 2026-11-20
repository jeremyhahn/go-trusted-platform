import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PlatformClient, PlatformProvider } from "trusted-platform-sdk";

import DeviceLookupPage from "./page";

// #1743 Codex round 4: the activation card. POST /device/activate-json
// (CRUDHandler.ActivateDevice) only resolves the VLAN the matching profile
// admits; it programs no switch. These tests stub fetch, the boundary the
// browser crosses, with the envelopes the webservice writes.

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

describe("DeviceLookupPage activation", () => {
  const fetchMock = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: fetchMock,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <DeviceLookupPage />
      </PlatformProvider>
    );
  }

  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      const body = typeof init?.body === "string" ? JSON.parse(init.body) : undefined;
      if (method === "POST" && url.pathname.endsWith("/device/activate-json")) {
        if (body?.serial === "SN-A") {
          return Promise.resolve(ok({ status: "activated", vlan: 20 }));
        }
        return Promise.resolve(failure(404, "device not found"));
      }
      return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
    });
  });

  afterEach(() => {
    cleanup();
  });

  async function activate(serial: string, mac: string) {
    fireEvent.change(screen.getByLabelText("Serial"), { target: { value: serial } });
    fireEvent.change(screen.getByLabelText("MAC address"), { target: { value: mac } });
    fireEvent.click(screen.getByRole("button", { name: "Activate device" }));
    const dialog = await screen.findByRole("dialog");
    const description = dialog.textContent ?? "";
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Confirm" }));
    });
    return description;
  }

  it("describes the lookup the endpoint performs, never a switch transition", async () => {
    renderPage();
    const description = await activate("SN-A", "52:54:00:00:00:0a");

    expect(description).not.toMatch(/switch port moves/i);
    expect(description).toMatch(/does not program the switch/i);
    const result = await screen.findByTestId("activate-result");
    expect(result.textContent).toMatch(/admitted VLAN 20/i);
    expect(result.textContent).toMatch(/switch not changed/i);
  });

  it("drops device A's result when a later activation of device B fails", async () => {
    renderPage();
    await activate("SN-A", "52:54:00:00:00:0a");
    await screen.findByTestId("activate-result");

    await activate("SN-B", "52:54:00:00:00:0b");
    await waitFor(() => {
      const calls = fetchMock.mock.calls.filter(([input]) =>
        new URL(String(input)).pathname.endsWith("/device/activate-json")
      );
      expect(calls).toHaveLength(2);
    });

    await waitFor(() => expect(screen.queryByTestId("activate-result")).toBeNull());
  });

  it("drops the result as soon as the target serial changes", async () => {
    renderPage();
    await activate("SN-A", "52:54:00:00:00:0a");
    await screen.findByTestId("activate-result");

    fireEvent.change(screen.getByLabelText("Serial"), { target: { value: "SN-B" } });

    expect(screen.queryByTestId("activate-result")).toBeNull();
  });
});

// Pasted evidence is verified against the nonce it carries and with no
// evidence age limit, so an old quote replays as a fresh verdict. The page
// offers no paste-and-verify control until a challenge-based flow exists
// (#2024 Codex round 4, P1).
describe("DeviceLookupPage attestation", () => {
  const lookupFetch = vi.fn();

  beforeEach(() => {
    lookupFetch.mockReset();
    lookupFetch.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      if (method === "GET" && url.pathname.endsWith("/devices/serial/SN-1")) {
        return Promise.resolve(ok({ id: "5", serial: "SN-1", model: "Board-A", hash_algo_id: 11 }));
      }
      return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("offers no pasted-evidence verification and sends no attest call", async () => {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: lookupFetch,
      retry: { maxRetries: 0 },
    });
    render(
      <PlatformProvider client={client}>
        <DeviceLookupPage />
      </PlatformProvider>
    );

    fireEvent.change(screen.getByLabelText("Device serial"), { target: { value: "SN-1" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Find device" }));
    });
    await screen.findByRole("button", { name: "Update device" });

    expect(screen.queryByLabelText(/attestation evidence/i)).toBeNull();
    // The only attest control is the gated one (#2048): disabled, no call.
    for (const button of screen.queryAllByRole("button", { name: /attest/i })) {
      expect(button).toHaveProperty("disabled", true);
      fireEvent.click(button);
    }
    const attestCalls = lookupFetch.mock.calls.filter(([input]) => String(input).includes("/attest"));
    expect(attestCalls).toEqual([]);
  });
});

// #2048: the row's operations an operator session cannot perform are gated
// controls with their reason; GetProfile by ID is a live lookup.
describe("DeviceLookupPage device operations", () => {
  const rowFetch = vi.fn<typeof fetch>();

  function renderPage() {
    const client = new PlatformClient({
      baseUrl: "https://platform.test/api",
      fetch: rowFetch,
      retry: { maxRetries: 0 },
    });
    return render(
      <PlatformProvider client={client}>
        <DeviceLookupPage />
      </PlatformProvider>
    );
  }

  beforeEach(() => {
    rowFetch.mockReset();
    rowFetch.mockImplementation((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      if (method === "GET" && url.pathname.endsWith("/device/profiles/7")) {
        return Promise.resolve(ok({ id: "7", name: "edge-a", model: "Board-A" }));
      }
      return Promise.resolve(failure(404, `no route ${method} ${url.pathname}`));
    });
  });

  afterEach(() => {
    cleanup();
  });

  it.each([
    ["Verify attestation", "AttestDevice"],
    ["Load device profile", "GetProfile"],
    ["Fetch boot certificate", "BootCertificate"],
    ["Request boot delivery", "BootDelivery"],
  ])("gates %s off with its reason and sends nothing", (name, operation) => {
    renderPage();

    const button = screen.getByRole("button", { name });
    expect(button).toHaveProperty("disabled", true);
    expect(screen.getByTestId(`device-gate-${operation}`).textContent).toMatch(/\w/);
    fireEvent.click(button);
    const sent = rowFetch.mock.calls.filter(([input]) => {
      const path = new URL(String(input)).pathname;
      return /\/attest$|\/device\/profile$|\/device\/boot/.test(path);
    });
    expect(sent).toEqual([]);
  });

  it("finds a profile by ID and shows it for editing", async () => {
    renderPage();

    fireEvent.change(screen.getByLabelText("Profile ID"), { target: { value: "7" } });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Find by ID" }));
    });

    await waitFor(() => expect(screen.getByLabelText("Profile name")).toHaveProperty("value", "edge-a"));
    const byId = rowFetch.mock.calls.filter(([input]) =>
      new URL(String(input)).pathname.endsWith("/device/profiles/7")
    );
    expect(byId).toHaveLength(1);
  });
});
