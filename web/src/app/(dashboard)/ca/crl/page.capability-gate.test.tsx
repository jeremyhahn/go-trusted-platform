import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the CRL page reads GET /api/v1/ca/crl through useCA (network
// boundary, mocked here) only when the server offers it, and gates Refresh,
// Download PEM and Download DER on that op.

const { ca, toast, capability, caps } = vi.hoisted(() => ({
  ca: { getCRL: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCA: () => ca,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

import CRLPage from "./page";

const CRL_OP = "GET /api/v1/ca/crl";
const REASON = "blocked: integration";
const CRL = {
  data: btoa("crl-der-bytes"),
  lastUpdate: "2026-11-01T00:00:00Z",
  nextUpdate: "2026-12-01T00:00:00Z",
  revokedCerts: [{ serial: "0a1b2c", reason: "keyCompromise", revocationTime: "2026-11-02T00:00:00Z" }],
};

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: string): HTMLButtonElement {
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
    expect(el.getAttribute("data-capability-enabled")).toBe("false");
  }
}

beforeEach(() => {
  ca.getCRL.mockReset();
  ca.getCRL.mockResolvedValue({ data: { crl: CRL } });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("CRLPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/ca/crl is not offered", async () => {
    offExcept([CRL_OP]);
    render(<CRLPage />);

    const card = await screen.findByTestId("ca-crl-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(ca.getCRL).not.toHaveBeenCalled();
    expectWithheld(button("Refresh"), CRL_OP);
    expectWithheld(button("Download PEM"), CRL_OP);
    expectWithheld(button("Download DER"), CRL_OP);
  });

  it("shows the loading state and does not read while the capabilities load", async () => {
    caps.loading = true;
    offExcept([CRL_OP]);
    render(<CRLPage />);

    expect(await screen.findByText("Loading CRL...")).toBeTruthy();
    expect(screen.queryByTestId("ca-crl-not-enabled")).toBeNull();
    expect(ca.getCRL).not.toHaveBeenCalled();
  });

  it("renders the CRL and leaves Refresh and both downloads enabled when the server offers the read", async () => {
    render(<CRLPage />);

    expect(await screen.findByText("0a1b2c")).toBeTruthy();
    expect(capability).toHaveBeenCalledWith(CRL_OP);
    expect(ca.getCRL).toHaveBeenCalled();
    expect(screen.queryByTestId("ca-crl-not-enabled")).toBeNull();
    for (const name of ["Refresh", "Download PEM", "Download DER"]) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
  });
});
