import * as React from "react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import VTPMRuntimeClient from "./vtpm-runtime-client";

// #2072: every vTPM runtime control follows GET /api/v1/capabilities through
// the shared capability gate; a control the server does not offer is
// disabled, never hidden.

vi.mock("next/navigation", () => ({
  usePathname: () => "/tpm/vtpm/b1",
}));

function mutation() {
  return { isLoading: false, data: undefined, mutateAsync: vi.fn() };
}

const runtime = {
  runState: "unknown",
  lifecycleBusy: false,
  checkState: mutation(),
  start: mutation(),
  stop: mutation(),
  quote: mutation(),
  seal: mutation(),
  unseal: mutation(),
  readPCR: mutation(),
  extendPCR: mutation(),
};

vi.mock("@/hooks", async (importActual) => {
  const actual = await importActual<typeof import("@/hooks")>();
  return {
    ...actual,
    textToBase64: actual.textToBase64,
    base64ToText: actual.base64ToText,
    hexToBase64: actual.hexToBase64,
    base64ToHex: actual.base64ToHex,
    useVTPMRuntime: () => runtime,
    useToast: () => ({ toast: vi.fn() }),
  };
});

let disabledOps: string[] = [];

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: null,
    capability: (op: string) =>
      disabledOps.includes(op) ? { enabled: false, reason: "not offered by this server" } : { enabled: true },
  }),
}));

const controls: Array<[string, string]> = [
  ["Check state", "GET /api/v1/vtpm/bundles/{id}/state"],
  ["Start vTPM", "POST /api/v1/vtpm/bundles/{id}/start"],
  ["Stop vTPM", "POST /api/v1/vtpm/bundles/{id}/stop"],
  ["Quote", "POST /api/v1/vtpm/bundles/{id}/quote"],
  ["Seal", "POST /api/v1/vtpm/bundles/{id}/seal"],
  ["Unseal", "POST /api/v1/vtpm/bundles/{id}/unseal"],
  ["Read PCR", "GET /api/v1/vtpm/bundles/{id}/pcrs"],
  ["Extend PCR", "POST /api/v1/vtpm/bundles/{id}/pcrs/extend"],
];

async function renderPage() {
  const params = Promise.resolve({ id: "b1" });
  await act(async () => {
    render(
      <React.Suspense fallback={null}>
        <VTPMRuntimeClient params={params} />
      </React.Suspense>
    );
  });
  await screen.findByRole("button", { name: "Check state" });
}

describe("vTPM runtime capability gate", () => {
  beforeEach(() => {
    disabledOps = [];
  });

  afterEach(() => {
    cleanup();
  });

  it("disables each runtime control the server does not offer", async () => {
    disabledOps = controls.map(([, op]) => op);
    await renderPage();
    for (const [name, op] of controls) {
      const button = screen.getByRole("button", { name });
      expect(button.getAttribute("data-capability-op"), name).toBe(op);
      expect(button.getAttribute("data-capability-enabled"), name).toBe("false");
      expect((button as HTMLButtonElement).disabled, name).toBe(true);
    }
  });

  it("enables the runtime controls the server offers", async () => {
    await renderPage();
    for (const [name, op] of controls) {
      const button = screen.getByRole("button", { name });
      expect(button.getAttribute("data-capability-op"), name).toBe(op);
      expect(button.getAttribute("data-capability-enabled"), name).toBe("true");
    }
    // The gate leaves each control's own rule in place: Check state is live.
    expect((screen.getByRole("button", { name: "Check state" }) as HTMLButtonElement).disabled).toBe(false);
  });
});

describe("vTPM runtime socket", () => {
  const initial = { ...runtime };

  afterEach(() => {
    cleanup();
    Object.assign(runtime, initial);
  });

  it("after Start, Check state, Stop, Start shows the socket of the last start", async () => {
    // The hook state Start, Check state, Stop, Start leaves: the old state
    // reply is still in checkState.data, the hook's socket is the new start's.
    Object.assign(runtime, {
      runState: "running",
      socketPath: "/run/vtpm/start.sock",
      start: { ...mutation(), data: { bundle_id: "b1", running: true, socket_path: "/run/vtpm/start.sock" } },
      checkState: { ...mutation(), data: { bundle_id: "b1", running: true, socket_path: "/run/vtpm/state.sock" } },
      stop: { ...mutation(), data: { bundle_id: "b1", stopped: true } },
    });
    await renderPage();
    expect(screen.getByTestId("vtpm-socket").textContent).toBe("/run/vtpm/start.sock");
  });
});
