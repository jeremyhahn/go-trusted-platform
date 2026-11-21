import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import EventLogsPage from "./page";

// #2038: the server answers ListManifests through protojson, which writes the
// PCR algorithm enum by its full proto name. The page must show the short name
// so the Algorithm filter (option values "SHA256", "SHA384", ...) matches rows.

let manifestsData: unknown;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => "/attestation/eventlogs",
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useAttestation: () => ({ listManifests: vi.fn() }),
  useToast: () => ({ toast: vi.fn() }),
  useApi: () => ({
    data: manifestsData,
    isLoading: false,
    error: null,
    refetch: vi.fn(),
  }),
}));

function manifests(hostAlg: string, vmAlg: string) {
  return {
    manifests: [
      {
        id: "m-1",
        hostId: "host-a",
        timestamp: "2026-08-31T00:00:00Z",
        host: { pcrs: [{ index: 0, algorithm: hostAlg, value: "AAAA" }] },
        vms: [
          {
            vmId: "vm-1",
            timestamp: "2026-08-31T00:00:00Z",
            pcrs: [{ index: 7, algorithm: vmAlg, value: "BBBB" }],
          },
        ],
      },
    ],
  };
}

describe("EventLogsPage digest algorithm", () => {
  afterEach(() => {
    cleanup();
  });

  it("shows the short algorithm name for proto enum names", () => {
    manifestsData = manifests(
      "ATTESTATION_HASH_ALGORITHM_SHA256",
      "ATTESTATION_HASH_ALGORITHM_SHA384"
    );
    render(<EventLogsPage />);

    expect(screen.getAllByText("SHA256").length).toBeGreaterThan(0);
    expect(screen.getAllByText("SHA384").length).toBeGreaterThan(0);
    expect(document.body.textContent ?? "").not.toMatch(
      /ATTESTATION_HASH_ALGORITHM_/
    );
  });

  it("keeps a short algorithm name unchanged", () => {
    manifestsData = manifests("SHA512", "SHA512");
    render(<EventLogsPage />);

    expect(screen.getAllByText("SHA512").length).toBeGreaterThan(0);
  });
});
