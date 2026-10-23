import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import AttestationPage from "./page";

// #643: the page reported "Total 2, Verified 0, Failed 0, Pending 2" for two
// manifests with no host section and no verifier verdict at all, and showed
// it as a clean dashboard. The summary now counts the verifier's verdicts and
// names the states nobody is acting on.

const service = {
  listManifests: vi.fn(),
  listDeviceReports: vi.fn(),
  buildManifest: vi.fn(),
};

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => service,
  useToast: () => ({ toast: vi.fn() }),
}));

// The two manifests the issue measured: no host section, no signature.
const unsignedManifests = {
  data: {
    manifests: [
      { id: "m-1", hostId: "lab-node-1", timestamp: "2026-08-31T00:00:00Z" },
      { id: "m-2", hostId: "lab-node-2", timestamp: "2026-08-31T00:00:00Z" },
    ],
  },
  success: true,
};

function report(deviceId: string, verified: boolean, cryptographicFailure: boolean, fresh: boolean) {
  return {
    device_id: deviceId,
    verified,
    cryptographic_failure: cryptographicFailure,
    fresh,
    age_seconds: fresh ? 42 : 7200,
  };
}

function reports(...items: ReturnType<typeof report>[]) {
  return { data: { reports: items, count: items.length }, success: true };
}

describe("AttestationPage verdict summary", () => {
  beforeEach(() => {
    service.listManifests.mockResolvedValue(unsignedManifests);
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
  });

  it("flags a fleet with manifests but no verdict instead of calling it pending", async () => {
    service.listDeviceReports.mockResolvedValue(reports());
    render(<AttestationPage />);

    const problems = await screen.findByTestId("attestation-fleet-problems");
    expect(problems.textContent).toContain("No device has an attestation verdict");
    expect(screen.getByTestId("attestation-stat-total").textContent).toBe("0");
    expect(screen.getByTestId("attestation-stat-verified").textContent).toBe("0");
    expect(screen.queryByText("Pending")).toBeNull();
    expect(await screen.findAllByText("Unsigned")).toHaveLength(2);
  });

  it("counts verdicts from the verifier and names stale and unverdicted devices", async () => {
    service.listDeviceReports.mockResolvedValue(
      reports(report("1", true, false, true), report("2", false, false, false))
    );
    render(<AttestationPage />);

    const problems = await screen.findByTestId("attestation-fleet-problems");
    expect(screen.getByTestId("attestation-stat-total").textContent).toBe("2");
    expect(screen.getByTestId("attestation-stat-verified").textContent).toBe("1");
    expect(screen.getByTestId("attestation-stat-failed").textContent).toBe("0");
    expect(screen.getByTestId("attestation-stat-not-verified").textContent).toBe("1");
    expect(screen.getByTestId("attestation-stat-stale").textContent).toContain("1 stale");
    expect(problems.textContent).toContain("1 device reached no verdict");
    expect(problems.textContent).toContain("1 device past the collector TTL");
  });

  it("shows no problem when every device is verified on fresh evidence", async () => {
    service.listDeviceReports.mockResolvedValue(
      reports(report("1", true, false, true), report("2", true, false, true))
    );
    render(<AttestationPage />);

    await vi.waitFor(() =>
      expect(screen.getByTestId("attestation-stat-verified").textContent).toBe("2")
    );
    expect(screen.queryByTestId("attestation-fleet-problems")).toBeNull();
  });

  it("says so when the reporting service is not configured", async () => {
    service.listDeviceReports.mockResolvedValue({
      error: { status: 503, message: "attestation reporting is not configured" },
      success: false,
    });
    render(<AttestationPage />);

    const problems = await screen.findByTestId("attestation-fleet-problems");
    expect(problems.textContent).toContain("Attestation reporting is not configured on this node");
  });
});
