import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the TPM seal page seals and unseals through useTPM (network
// boundary, mocked here; useMutation stays real) and gates Seal and Unseal on
// the server's capabilities.

const { tpm, toast, capability } = vi.hoisted(() => ({
  tpm: { seal: vi.fn(), unseal: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useTPM: () => tpm,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

import TPMSealPage from "./page";

const SEAL_OP = "POST /api/v1/tpm/seal";
const UNSEAL_OP = "POST /api/v1/tpm/unseal";
const REASON = "blocked: integration";

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

function fillSeal() {
  fireEvent.change(document.getElementById("seal-cn") as HTMLElement, { target: { value: "disk-key" } });
  fireEvent.change(document.getElementById("seal-data") as HTMLElement, { target: { value: "secret" } });
}

async function openUnsealTab() {
  fireEvent.mouseDown(screen.getByRole("tab", { name: /Unseal Data/ }), { button: 0 });
  await waitFor(() => expect(document.getElementById("unseal-cn")).not.toBeNull());
  fireEvent.change(document.getElementById("unseal-cn") as HTMLElement, { target: { value: "disk-key" } });
}

beforeEach(() => {
  tpm.seal.mockReset();
  tpm.seal.mockResolvedValue({ sealedData: "c2VhbGVk" });
  tpm.unseal.mockReset();
  tpm.unseal.mockResolvedValue({ data: btoa("secret") });
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("TPMSealPage capability gate", () => {
  it("withholds Seal with its inputs filled when POST /api/v1/tpm/seal is not offered", () => {
    offExcept([SEAL_OP]);
    render(<TPMSealPage />);
    fillSeal();

    const seal = button("Seal Data");
    expectWithheld(seal, SEAL_OP);
    fireEvent.click(seal);
    expect(tpm.seal).not.toHaveBeenCalled();
    expect(screen.queryByTestId("tpm-seal-not-enabled")).toBeNull();
  });

  it("withholds Unseal with its input filled when POST /api/v1/tpm/unseal is not offered", async () => {
    offExcept([UNSEAL_OP]);
    render(<TPMSealPage />);
    await openUnsealTab();

    const unseal = button("Unseal Data");
    expectWithheld(unseal, UNSEAL_OP);
    fireEvent.click(unseal);
    expect(tpm.unseal).not.toHaveBeenCalled();
  });

  it("shows the not-enabled card with the server's reason when neither op is offered", () => {
    offExcept([SEAL_OP, UNSEAL_OP]);
    render(<TPMSealPage />);

    const card = screen.getByTestId("tpm-seal-not-enabled");
    expect(card.textContent).toContain(REASON);
    const tabs = screen.getAllByRole("tablist")[0];
    expect(card.compareDocumentPosition(tabs) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("leaves Seal and Unseal enabled once their inputs are filled when the server offers them", async () => {
    render(<TPMSealPage />);
    expect(screen.queryByTestId("tpm-seal-not-enabled")).toBeNull();
    fillSeal();

    const seal = button("Seal Data");
    expect(seal.disabled).toBe(false);
    expect(seal.getAttribute("data-capability-enabled")).toBe("true");
    fireEvent.click(seal);
    await waitFor(() => expect(tpm.seal).toHaveBeenCalled());

    await openUnsealTab();
    const unseal = button("Unseal Data");
    expect(unseal.disabled).toBe(false);
    expect(unseal.getAttribute("data-capability-enabled")).toBe("true");
    expect(capability).toHaveBeenCalledWith(SEAL_OP);
    expect(capability).toHaveBeenCalledWith(UNSEAL_OP);
  });
});
