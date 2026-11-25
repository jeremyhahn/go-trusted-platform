import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the SDN page creates bridges through useSDN (network
// boundary, mocked here) and gates Create Network and the dialog's Create on
// the server's capabilities.

const { sdn, toast, capability } = vi.hoisted(() => ({
  sdn: { listBridges: vi.fn(), listFlows: vi.fn(), createBridge: vi.fn() },
  toast: vi.fn(),
  capability: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useSDN: () => sdn,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated reads the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({ useCapabilities: () => ({ loading: false, error: undefined, capability }) }));

// The topology graph is not under test and needs a canvas layout.
vi.mock("@/components/features/networking/sdn-topology", () => ({ SDNTopology: () => null }));

import SDNPage from "./page";

const CREATE_OP = "POST /api/v1/sdn/bridges";

function createNetworkButton(): HTMLButtonElement {
  return screen.getByText("Create Network", { selector: "button" }) as HTMLButtonElement;
}

beforeEach(() => {
  for (const fn of Object.values(sdn)) fn.mockReset();
  sdn.listBridges.mockResolvedValue({ success: true, data: { bridges: [] } });
  sdn.listFlows.mockResolvedValue({ success: true, data: { flows: [] } });
  toast.mockReset();
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
});

afterEach(() => {
  cleanup();
});

describe("SDNPage capability gate", () => {
  it("withholds Create Network with the server's reason when POST /api/v1/sdn/bridges is not offered", async () => {
    capability.mockImplementation((op: string) =>
      op === CREATE_OP ? { enabled: false, reason: "not-configured: sdn" } : { enabled: true },
    );
    render(<SDNPage />);
    await waitFor(() => expect(sdn.listBridges).toHaveBeenCalled());

    const create = createNetworkButton();
    expect(create.disabled).toBe(true);
    expect(create.getAttribute("title")).toBe("not-configured: sdn");
    expect(create.getAttribute("data-capability-op")).toBe(CREATE_OP);
    expect(create.getAttribute("data-capability-enabled")).toBe("false");

    fireEvent.click(create);
    expect(screen.queryByText("Create Network (Bridge)")).toBeNull();
    expect(sdn.createBridge).not.toHaveBeenCalled();
  });

  it("asks the gate for POST /api/v1/sdn/bridges and leaves Create Network enabled when the server offers it", async () => {
    render(<SDNPage />);
    await waitFor(() => expect(sdn.listBridges).toHaveBeenCalled());

    expect(capability).toHaveBeenCalledWith(CREATE_OP);
    const create = createNetworkButton();
    expect(create.getAttribute("data-capability-enabled")).toBe("true");

    fireEvent.click(create);
    await screen.findByText("Create Network (Bridge)");
    expect(screen.getByRole("button", { name: "Create" }).getAttribute("data-capability-op")).toBe(CREATE_OP);
  });
});
