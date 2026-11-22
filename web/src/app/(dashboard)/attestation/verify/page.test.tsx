import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import VerifyPage from "./page";

// #2038: the verify page labelled every signed manifest "Passed" without
// asking the verifier, and its Run Verification button did nothing. The
// Result column now shows the verdict AttestationService.VerifyManifest
// returns, and a manifest nobody has verified is "Not verified".

const service = {
  listManifests: vi.fn(),
  verifyManifest: vi.fn(),
};

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => service,
  useToast: () => ({ toast: vi.fn() }),
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

const manifestA = {
  id: "m-1",
  hostId: "node-a",
  timestamp: "2026-08-31T00:00:00Z",
  signature: "c2ln",
  merkleRoot: "cm9vdA==",
};

const manifestB = {
  id: "m-2",
  hostId: "node-b",
  timestamp: "2026-08-31T00:00:00Z",
  signature: "c2ln",
  merkleRoot: "cm9vdA==",
};

function row(hostId: string): HTMLElement {
  // The device cell shows the host id twice (name and id).
  const tr = screen.getAllByText(hostId)[0].closest("tr");
  if (!tr) throw new Error(`no row for ${hostId}`);
  return tr as HTMLElement;
}

describe("VerifyPage verifier verdicts", () => {
  beforeEach(() => {
    service.listManifests.mockResolvedValue({
      data: { manifests: [manifestA, manifestB] },
      success: true,
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    off.clear();
  });

  it("shows a signed manifest as not verified before any run", async () => {
    render(<VerifyPage />);
    await screen.findAllByText("node-a");

    for (const host of ["node-a", "node-b"]) {
      expect(within(row(host)).queryByText("Passed")).toBeNull();
      expect(within(row(host)).getByText("Not verified")).toBeTruthy();
    }
    expect(service.verifyManifest).not.toHaveBeenCalled();
  });

  it("runs VerifyManifest per manifest and shows each verdict", async () => {
    service.verifyManifest.mockImplementation(
      async ({ manifest }: { manifest: { id: string } }) => ({
        success: true,
        data: {
          status: "SUCCESS",
          result: { status: manifest.id === "m-1" ? "VERIFIED" : "FAILED" },
        },
      })
    );
    render(<VerifyPage />);
    await screen.findAllByText("node-a");

    fireEvent.click(screen.getByRole("button", { name: /Run Verification/ }));

    await vi.waitFor(() =>
      expect(within(row("node-a")).getByText("Passed")).toBeTruthy()
    );
    expect(within(row("node-b")).getByText("Failed")).toBeTruthy();
    expect(service.verifyManifest).toHaveBeenCalledTimes(2);
    expect(service.verifyManifest).toHaveBeenCalledWith({ manifest: manifestA });
    expect(service.verifyManifest).toHaveBeenCalledWith({ manifest: manifestB });
  });

  it("leaves a manifest not verified when the verify call fails", async () => {
    service.verifyManifest.mockResolvedValue({
      success: false,
      error: { message: "boom" },
    });
    render(<VerifyPage />);
    await screen.findAllByText("node-a");

    fireEvent.click(screen.getByRole("button", { name: /Run Verification/ }));

    await vi.waitFor(() => expect(service.verifyManifest).toHaveBeenCalledTimes(2));
    await vi.waitFor(() =>
      expect(
        (screen.getByRole("button", { name: /Run Verification/ }) as HTMLButtonElement)
          .disabled
      ).toBe(false)
    );
    for (const host of ["node-a", "node-b"]) {
      expect(within(row(host)).getByText("Not verified")).toBeTruthy();
      expect(within(row(host)).queryByText("Passed")).toBeNull();
    }
  });

  it("withholds Run Verification when the server does not offer it", async () => {
    off.add("POST /api/v1/attestation/manifests/verify");
    render(<VerifyPage />);
    await screen.findAllByText("node-a");

    const button = screen.getByRole("button", { name: /Run Verification/ }) as HTMLButtonElement;
    expect(button.getAttribute("data-capability-op")).toBe("POST /api/v1/attestation/manifests/verify");
    expect(button.getAttribute("data-capability-enabled")).toBe("false");
    expect(button.disabled).toBe(true);
    expect(button.getAttribute("title")).toBe("not-configured: attestation");
  });
});
