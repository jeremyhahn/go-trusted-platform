import * as React from "react";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the TPM NVRAM page reads /api/v1/tpm/info and drives the NV
// index operations through useTPM (network boundary, mocked here) only when
// the server offers them, and gates every control on its route.

const { tpm, toast, capability, caps } = vi.hoisted(() => ({
  tpm: {
    getInfo: vi.fn(),
    readNVRAM: vi.fn(),
    defineNVRAM: vi.fn(),
    writeNVRAM: vi.fn(),
    undefineNVRAM: vi.fn(),
  },
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

import TPMNVRAMPage from "./page";

const INFO_OP = "GET /api/v1/tpm/info";
const DEFINE_OP = "POST /api/v1/tpm/nvram";
const READ_OP = "GET /api/v1/tpm/nvram/{index}";
const WRITE_OP = "PUT /api/v1/tpm/nvram/{index}";
const UNDEFINE_OP = "DELETE /api/v1/tpm/nvram/{index}";
const REASON = "blocked: integration";

const info = {
  capabilities: [],
  nvIndexes: [{ handle: 0x01500001, type: "ordinary", size: 32, authRead: true, authWrite: true }],
};

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function button(name: RegExp | string): HTMLButtonElement {
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

async function indexRow(): Promise<HTMLElement> {
  const handle = await screen.findByText("0x01500001");
  return handle.closest("tr") as HTMLElement;
}

function rowButton(row: HTMLElement, op: string): HTMLButtonElement {
  const el = row.querySelector(`button[data-capability-op="${op}"]`);
  expect(el).not.toBeNull();
  return el as HTMLButtonElement;
}

function noTPMCalls() {
  expect(tpm.readNVRAM).not.toHaveBeenCalled();
  expect(tpm.defineNVRAM).not.toHaveBeenCalled();
  expect(tpm.writeNVRAM).not.toHaveBeenCalled();
  expect(tpm.undefineNVRAM).not.toHaveBeenCalled();
}

beforeEach(() => {
  for (const fn of Object.values(tpm)) fn.mockReset();
  tpm.getInfo.mockResolvedValue({ data: info });
  tpm.readNVRAM.mockResolvedValue({ data: { data: "" } });
  tpm.defineNVRAM.mockResolvedValue({ data: {} });
  tpm.writeNVRAM.mockResolvedValue({ data: {} });
  tpm.undefineNVRAM.mockResolvedValue({ data: {} });
  toast.mockReset();
  caps.loading = false;
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  vi.spyOn(window, "confirm").mockReturnValue(true);
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TPMNVRAMPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/tpm/info is not offered", async () => {
    offExcept([INFO_OP]);
    render(<TPMNVRAMPage />);

    const card = await screen.findByTestId("tpm-nvram-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(tpm.getInfo).not.toHaveBeenCalled();
    expect(screen.queryByText("Loading NVRAM info…")).toBeNull();
    expectWithheld(button("Refresh"), INFO_OP);
  });

  it("shows the spinner and waits for the capabilities before reading", () => {
    caps.loading = true;
    render(<TPMNVRAMPage />);

    expect(screen.getByText("Loading NVRAM info…")).toBeTruthy();
    expect(screen.queryByTestId("tpm-nvram-not-enabled")).toBeNull();
    expect(tpm.getInfo).not.toHaveBeenCalled();
  });

  it("withholds Define Index when POST /api/v1/tpm/nvram is not offered", async () => {
    offExcept([DEFINE_OP]);
    render(<TPMNVRAMPage />);
    await indexRow();

    const define = button(/Define Index/);
    expectWithheld(define, DEFINE_OP);
    fireEvent.click(define);
    expect(screen.queryByText(/Define New NV Index/)).toBeNull();
    noTPMCalls();
  });

  it("withholds the row Read, Write and Undefine when their ops are not offered", async () => {
    offExcept([READ_OP, WRITE_OP, UNDEFINE_OP]);
    render(<TPMNVRAMPage />);
    const row = await indexRow();

    for (const op of [READ_OP, WRITE_OP, UNDEFINE_OP]) {
      const el = rowButton(row, op);
      expectWithheld(el, op);
      fireEvent.click(el);
    }
    expect(within(row).getAllByRole("button")).toHaveLength(3);
    expect(screen.queryByText(/Read NV Index/)).toBeNull();
    expect(screen.queryByText(/Write NV Index/)).toBeNull();
    noTPMCalls();
  });

  it("leaves every control enabled when the server offers the NVRAM ops", async () => {
    render(<TPMNVRAMPage />);
    const row = await indexRow();

    await waitFor(() => expect(tpm.getInfo).toHaveBeenCalled());
    expect(screen.queryByTestId("tpm-nvram-not-enabled")).toBeNull();
    for (const op of [INFO_OP, DEFINE_OP, READ_OP, WRITE_OP, UNDEFINE_OP]) {
      expect(capability).toHaveBeenCalledWith(op);
    }
    for (const name of [/Define Index/, "Refresh"]) {
      const el = button(name);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
    for (const op of [READ_OP, WRITE_OP, UNDEFINE_OP]) {
      const el = rowButton(row, op);
      expect(el.disabled).toBe(false);
      expect(el.getAttribute("data-capability-enabled")).toBe("true");
    }
  });
});
