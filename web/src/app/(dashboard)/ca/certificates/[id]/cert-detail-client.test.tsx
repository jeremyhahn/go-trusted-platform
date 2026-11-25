// #2041: GetCertificate is protojson, so status is the CertificateStatus enum name (pkg/webservice/v1/rest/ca/handlers.go certToProto).
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

// Main gates this page on the server's capabilities (#2033); these cases run
// with every op offered (the gating has its own tests).
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: false, error: undefined, capability: () => ({ enabled: true }) }),
}));
import { Suspense } from "react";
import CertificateDetailPage from "./cert-detail-client";

vi.mock("next/navigation", () => ({
  usePathname: () => "/ca/certificates/0A",
  useRouter: () => ({ push: vi.fn() }),
}));

const api = vi.hoisted(() => ({ data: null as unknown }));

vi.mock("@/hooks", () => ({
  useCA: () => ({ getCertificate: vi.fn(), revokeCertificate: vi.fn() }),
  useToast: () => ({ toast: vi.fn() }),
  useApi: () => ({ data: api.data, isLoading: false, error: null, refetch: vi.fn() }),
  useMutation: () => ({ mutate: vi.fn(), isLoading: false }),
}));

vi.mock("@/components/features/ca/cert-detail", () => ({
  CertDetail: ({ certificate }: { certificate: { status: string } }) => (
    <div data-testid="cert-status">{certificate.status}</div>
  ),
}));

vi.mock("@/components/features/ca/cert-chain", () => ({ CertChain: () => null }));

async function renderWith(payload: unknown): Promise<string | null> {
  api.data = payload;
  await act(async () => {
    render(
      <Suspense fallback={null}>
        <CertificateDetailPage params={Promise.resolve({ id: "0A" })} />
      </Suspense>,
    );
  });
  return (await screen.findByTestId("cert-status")).textContent;
}

afterEach(() => {
  cleanup();
});

describe("CertificateDetailPage status", () => {
  it.each([
    ["CERTIFICATE_STATUS_EXPIRED", "expired"],
    ["CERTIFICATE_STATUS_REVOKED", "revoked"],
    ["CERTIFICATE_STATUS_VALID", "active"],
    ["CERTIFICATE_STATUS_PENDING", "active"],
    ["REVOKED", "revoked"],
    ["Expired", "expired"],
  ])("maps the wrapped status %s to %s", async (status, want) => {
    expect(await renderWith({ certificate: { serial: "0A", status } })).toBe(want);
  });

  it("maps the server's enum on an unwrapped certificate and its Status key", async () => {
    expect(await renderWith({ serial: "0A", Status: "CERTIFICATE_STATUS_EXPIRED" })).toBe("expired");
  });

  it("reads a missing status as active", async () => {
    expect(await renderWith({ serial: "0A" })).toBe("active");
  });
});
