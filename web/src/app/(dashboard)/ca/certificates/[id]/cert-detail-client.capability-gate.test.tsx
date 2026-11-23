import * as React from "react";
import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// #2033 item 5: the certificate detail page reads and revokes through useCA
// (network boundary, mocked here) and gates the read and Revoke on the
// server's capabilities.

const { ca, capability, caps, toast } = vi.hoisted(() => ({
  ca: { getCertificate: vi.fn(), revokeCertificate: vi.fn() },
  capability: vi.fn(),
  caps: { loading: false },
  toast: vi.fn(),
}));

vi.mock("@/hooks", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks")>()),
  useCA: () => ca,
  useToast: () => ({ toast }),
}));

// #2033 item 5: Gated and the page read the server's capabilities through this hook.
vi.mock("@/hooks/use-capabilities", () => ({
  useCapabilities: () => ({ loading: caps.loading, error: undefined, capability }),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), back: vi.fn(), refresh: vi.fn() }),
  usePathname: () => "/ca/certificates/0a1b2c3d",
}));

vi.mock("@/utils/dynamic-route", () => ({ resolveDynamicId: () => "0a1b2c3d" }));

import CertificateDetailPage from "./cert-detail-client";

const GET_OP = "GET /api/v1/ca/certificates/{serial}";
const REVOKE_OP = "DELETE /api/v1/ca/certificates/{serial}";
const REASON = "blocked: integration";

const cert = {
  serial: "0a1b2c3d",
  subject: { common_name: "leaf.example.com" },
  issuer: "Example Issuing CA",
  status: "VALID",
  not_before: Math.floor(Date.now() / 1000) - 86400,
  not_after: Math.floor(Date.now() / 1000) + 365 * 86400,
  key_algorithm: "ECDSA-P256",
};

function offExcept(off: string[]) {
  capability.mockImplementation((op: string) => (off.includes(op) ? { enabled: false, reason: REASON } : { enabled: true }));
}

function expectWithheld(el: HTMLElement, op?: string) {
  expect((el as HTMLButtonElement).disabled).toBe(true);
  expect(el.getAttribute("title")).toBe(REASON);
  if (op) {
    expect(el.getAttribute("data-capability-op")).toBe(op);
  }
}

async function renderPage() {
  const params = Promise.resolve({ id: "0a1b2c3d" });
  await act(async () => {
    render(
      <React.Suspense fallback={null}>
        <CertificateDetailPage params={params} />
      </React.Suspense>,
    );
  });
}

beforeEach(() => {
  ca.getCertificate.mockReset();
  ca.revokeCertificate.mockReset();
  ca.getCertificate.mockResolvedValue({ data: { certificate: cert } });
  ca.revokeCertificate.mockResolvedValue({ data: {} });
  capability.mockReset();
  capability.mockImplementation(() => ({ enabled: true }));
  caps.loading = false;
  toast.mockReset();
});

afterEach(() => {
  cleanup();
});

describe("CertificateDetailPage capability gate", () => {
  it("shows the not-enabled card with the server's reason and does not read when GET /api/v1/ca/certificates/{serial} is not offered", async () => {
    offExcept([GET_OP]);
    await renderPage();

    const card = await screen.findByTestId("ca-certificate-not-enabled");
    expect(card.textContent).toContain(REASON);
    expect(ca.getCertificate).not.toHaveBeenCalled();
    expect(screen.queryByText("Error loading certificate")).toBeNull();
    expect(screen.queryByText("Certificate not found")).toBeNull();
  });

  it("shows the spinner, not the not-found or error view, while the capabilities load", async () => {
    caps.loading = true;
    capability.mockImplementation(() => ({ enabled: false, reason: "loading" }));
    await renderPage();

    expect(document.querySelector(".animate-spin")).not.toBeNull();
    expect(screen.queryByText("Certificate not found")).toBeNull();
    expect(screen.queryByText("Error loading certificate")).toBeNull();
    expect(screen.queryByTestId("ca-certificate-not-enabled")).toBeNull();
    expect(ca.getCertificate).not.toHaveBeenCalled();
  });

  it("withholds Revoke on an active certificate when DELETE /api/v1/ca/certificates/{serial} is not offered", async () => {
    offExcept([REVOKE_OP]);
    await renderPage();

    const revoke = await screen.findByRole("button", { name: /Revoke/ });
    expectWithheld(revoke, REVOKE_OP);
  });

  it("enables Revoke when the server offers it", async () => {
    await renderPage();

    const revoke = (await screen.findByRole("button", { name: /Revoke/ })) as HTMLButtonElement;
    expect(ca.getCertificate).toHaveBeenCalled();
    expect(revoke.disabled).toBe(false);
  });
});
