import * as React from "react";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the CA bundle page reads GET /api/v1/ca/bundle through useCA
// (network boundary, mocked here) only when the server offers it, and gates
// Refresh and Download on that op.

const { ca, toast, capability, caps } = vi.hoisted(() => ({
  ca: { getBundle: vi.fn() },
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

import CABundlePage from "./page";

const BUNDLE_OP = "GET /api/v1/ca/bundle";
const REASON = "blocked: integration";
const PEM = "-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n";

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
  ca.getBundle.mockReset();
  ca.getBundle.mockResolvedValue({ data: { bundle: { pem: PEM } } });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("CABundlePage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/ca/bundle is not offered", async () => {
    offExcept([BUNDLE_OP]);
    render(<CABundlePage />);

    const card = await screen.findByTestId("ca-bundle-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(ca.getBundle).not.toHaveBeenCalled();
    expectWithheld(button("Refresh"), BUNDLE_OP);
    expectWithheld(button("Download"), BUNDLE_OP);
  });

  it("shows the loading state and does not read while the capabilities load", async () => {
    caps.loading = true;
    offExcept([BUNDLE_OP]);
    render(<CABundlePage />);

    expect(await screen.findByText("Loading CA bundle...")).toBeTruthy();
    expect(screen.queryByTestId("ca-bundle-not-enabled")).toBeNull();
    expect(screen.queryByText("No CA bundle available.")).toBeNull();
    expect(ca.getBundle).not.toHaveBeenCalled();
  });

  it("renders the bundle and leaves Refresh and Download enabled when the server offers the read", async () => {
    render(<CABundlePage />);

    expect(await screen.findByText(/MIIBtest/)).toBeTruthy();
    expect(capability).toHaveBeenCalledWith(BUNDLE_OP);
    expect(ca.getBundle).toHaveBeenCalled();
    expect(screen.queryByTestId("ca-bundle-not-enabled")).toBeNull();
    for (const name of ["Refresh", "Download"]) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
  });
});
