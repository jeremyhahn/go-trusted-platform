import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import AttestationCollectPage from "./page";

// #2038: the collect operations of the attestation service are reachable from
// a page that drives them through useAttestationCollect.

const collect = {
  collectHost: vi.fn(),
  collectVM: vi.fn(),
  collectContainer: vi.fn(),
};

vi.mock("@/hooks/use-attestation-collect", () => ({
  useAttestationCollect: () => collect,
}));

// The server's capability answers: every op enabled except those in off.
const off = new Set<string>();

vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({
    loading: false,
    error: undefined,
    capability: (op: string) =>
      off.has(op) ? { enabled: false, reason: "not-configured: attestation" } : { enabled: true },
  }),
}));

function type(testId: string, value: string) {
  fireEvent.change(screen.getByTestId(testId), { target: { value } });
}

describe("AttestationCollectPage", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    off.clear();
  });

  it("collects the host attestation with the typed PCR indices and nonce", async () => {
    collect.collectHost.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "collected" } },
    });
    render(<AttestationCollectPage />);

    type("collect-host-pcrs", "7, 11");
    type("collect-host-nonce", "bg==");
    fireEvent.click(screen.getByTestId("collect-host-submit"));

    const result = await screen.findByTestId("collect-host-result");
    expect(collect.collectHost).toHaveBeenCalledTimes(1);
    expect(collect.collectHost).toHaveBeenCalledWith({
      config: { pcrIndices: [7, 11] },
      nonce: "bg==",
    });
    expect(result.textContent).toContain("collected");
  });

  it("collects a VM attestation and shows a Verified badge", async () => {
    collect.collectVM.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" }, attestation: { vmId: "vm-1", hostId: "h-1", quoteData: "cXVvdGU=" } },
    });
    render(<AttestationCollectPage />);

    type("collect-vm-id", "vm-1");
    type("collect-vm-pcrs", "7");
    type("collect-vm-nonce", "bg==");
    fireEvent.click(screen.getByTestId("collect-vm-submit"));

    const result = await screen.findByTestId("collect-vm-result");
    expect(collect.collectVM).toHaveBeenCalledTimes(1);
    expect(collect.collectVM).toHaveBeenCalledWith({
      vmId: "vm-1",
      config: { pcrIndices: [7] },
      nonce: "bg==",
    });
    expect(result.textContent).toContain("Verified");
  });

  it("collects a container attestation and shows its digest", async () => {
    collect.collectContainer.mockResolvedValue({
      success: true,
      data: { status: { success: true, message: "" }, attestation: { containerId: "c-1", digest: "sha256:abc123", pcrValue: "00" } },
    });
    render(<AttestationCollectPage />);

    type("collect-container-id", "c-1");
    fireEvent.click(screen.getByTestId("collect-container-submit"));

    const result = await screen.findByTestId("collect-container-result");
    expect(collect.collectContainer).toHaveBeenCalledTimes(1);
    expect(collect.collectContainer).toHaveBeenCalledWith({ containerId: "c-1" });
    expect(result.textContent).toContain("sha256:abc123");
  });

  it("shows the refusal message in an alert", async () => {
    collect.collectContainer.mockResolvedValue({
      success: false,
      error: { status: 403, message: "container attestation is not permitted" },
    });
    render(<AttestationCollectPage />);

    type("collect-container-id", "c-1");
    fireEvent.click(screen.getByTestId("collect-container-submit"));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toContain("container attestation is not permitted");
  });

  it("sends nothing and shows an inline error for an invalid PCR index", async () => {
    render(<AttestationCollectPage />);

    type("collect-host-pcrs", "7, x");
    type("collect-host-nonce", "bg==");
    fireEvent.click(screen.getByTestId("collect-host-submit"));

    const error = await screen.findByTestId("collect-host-pcrs-error");
    expect(error.textContent).toContain("x");
    expect(collect.collectHost).not.toHaveBeenCalled();
  });

  it("withholds the collect controls the server does not offer", () => {
    const controls: Record<string, string> = {
      "collect-host-submit": "POST /api/v1/attestation/host",
      "collect-vm-submit": "POST /api/v1/attestation/vm/{id}",
      "collect-container-submit": "POST /api/v1/attestation/container/{id}",
    };
    for (const op of Object.values(controls)) off.add(op);
    render(<AttestationCollectPage />);

    for (const [testId, op] of Object.entries(controls)) {
      const button = screen.getByTestId(testId) as HTMLButtonElement;
      expect(button.getAttribute("data-capability-op")).toBe(op);
      expect(button.getAttribute("data-capability-enabled")).toBe("false");
      expect(button.disabled).toBe(true);
      expect(button.getAttribute("title")).toBe("not-configured: attestation");
    }
  });
});
