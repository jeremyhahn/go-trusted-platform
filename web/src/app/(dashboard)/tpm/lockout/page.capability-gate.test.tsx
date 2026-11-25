import * as React from "react";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the TPM lockout page reads /api/v1/tpm/info through useTPM
// (network boundary, mocked here) only when the server offers it, and gates
// Refresh on the same op.

const { tpm, toast, capability, caps } = vi.hoisted(() => ({
  tpm: { getInfo: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
  caps: { loading: false },
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

import TPMLockoutPage from "./page";

const INFO_OP = "GET /api/v1/tpm/info";
const REASON = "blocked: integration";

const info = {
  capabilities: [
    { name: "lockoutCounter", value: "1" },
    { name: "maxAuthFail", value: "32" },
    { name: "lockoutInterval", value: "7200" },
    { name: "lockoutRecovery", value: "86400" },
  ],
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
  tpm.getInfo.mockReset();
  tpm.getInfo.mockResolvedValue({ data: info });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("TPMLockoutPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/tpm/info is not offered", async () => {
    offExcept([INFO_OP]);
    render(<TPMLockoutPage />);

    const card = await screen.findByTestId("tpm-lockout-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(tpm.getInfo).not.toHaveBeenCalled();
    expectWithheld(button("Refresh"), INFO_OP);
  });

  it("waits for the capabilities before reading", async () => {
    caps.loading = true;
    render(<TPMLockoutPage />);

    await screen.findByRole("button", { name: "Refresh" });
    expect(screen.queryByTestId("tpm-lockout-not-enabled")).toBeNull();
    expect(tpm.getInfo).not.toHaveBeenCalled();
  });

  it("reads the TPM info and leaves Refresh enabled when the server offers it", async () => {
    render(<TPMLockoutPage />);

    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalled());
    expect(capability).toHaveBeenCalledWith(INFO_OP);
    expect(screen.queryByTestId("tpm-lockout-not-enabled")).toBeNull();
    await waitFor(() => expect(button("Refresh").disabled).toBe(false));
    expect(button("Refresh").getAttribute("data-capability-enabled")).toBe("true");
  });
});
