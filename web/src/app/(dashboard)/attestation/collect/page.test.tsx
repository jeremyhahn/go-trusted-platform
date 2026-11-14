import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import AttestationCollectPage from "./page";

// #1747 Codex round 2 (P1): VM and container collection always fail on the
// production service (ErrTPMSessionNotConfigured). The page shows them as
// unavailable and sends nothing, instead of offering controls that cannot work.

const service = {
  collectHostAttestation: vi.fn(),
  collectVMAttestation: vi.fn(),
  collectContainerAttestation: vi.fn(),
  deleteManifest: vi.fn(),
};

vi.mock("trusted-platform-sdk", () => ({
  useAttestation: () => service,
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useToast: () => ({ toast: vi.fn() }),
}));

describe("AttestationCollectPage workload collection", () => {
  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("gates VM and container collection with an unavailable notice", () => {
    render(<AttestationCollectPage />);

    expect(screen.getByTestId("workload-collect-unavailable").textContent).toContain(
      "not available"
    );

    const vmInput = screen.getByLabelText("VM ID") as HTMLInputElement;
    const containerInput = screen.getByLabelText("Container ID") as HTMLInputElement;
    fireEvent.change(vmInput, { target: { value: "vm-7" } });
    fireEvent.change(containerInput, { target: { value: "ctr-9" } });

    const vmButton = screen.getByRole("button", { name: "Collect VM attestation" });
    const containerButton = screen.getByRole("button", { name: "Collect container attestation" });
    expect((vmButton as HTMLButtonElement).disabled).toBe(true);
    expect((containerButton as HTMLButtonElement).disabled).toBe(true);
    expect(vmInput.disabled).toBe(true);
    expect(containerInput.disabled).toBe(true);

    fireEvent.click(vmButton);
    fireEvent.click(containerButton);
    expect(service.collectVMAttestation).not.toHaveBeenCalled();
    expect(service.collectContainerAttestation).not.toHaveBeenCalled();
  });

  it("keeps host collection available", () => {
    render(<AttestationCollectPage />);
    const hostButton = screen.getByRole("button", { name: "Collect host attestation" });
    expect((hostButton as HTMLButtonElement).disabled).toBe(false);
  });
});
