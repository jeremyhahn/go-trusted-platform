import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page creates the IAK CSR, installs the IDevID and IAK
// certificates and, after a confirm, deletes the IAK certificate through the
// IDevID service (useIDevIDCerts), over a stubbed fetch, and shows the answer
// or the refusal.

const tpmInfo = {
  version: "TPM_VERSION_2_0",
  manufacturer: null,
  capabilities: [],
  pcrBanks: ["PCR_BANK_SHA256"],
  maxNvramSize: 2048,
  isSimulator: false,
  fipsMode: false,
  properties: {},
  nvIndexes: [],
};

const CSR_PEM = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----";
const CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";

const toasts = () => screen.queryAllByTestId("toast").map((t) => t.textContent);

describe("TPMStatusPage identity certificates (#2055)", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("creates an IAK CSR and shows the PEM", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/iak/csr": ok({
        status: { success: true, message: "csr created" },
        csrPem: btoa(CSR_PEM),
      }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.change(await screen.findByLabelText("IAK CSR common name"), { target: { value: "dev-1" } });
    fireEvent.click(screen.getByRole("button", { name: "Create IAK CSR" }));

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: "POST",
        path: "/api/v1/idevid/iak/csr",
        body: { template: { commonName: "dev-1" } },
      })
    );
    expect((await screen.findByTestId("iak-csr-pem")).textContent).toBe(CSR_PEM);
  });

  it("installs the IDevID certificate from the pasted PEM", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/certificate": ok({ status: { success: true, message: "installed" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    const text = await screen.findByLabelText("IDevID certificate PEM");
    const button = screen.getByRole("button", { name: "Install IDevID certificate" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(text, { target: { value: "not a pem" } });
    expect(button.disabled).toBe(true);
    fireEvent.change(text, { target: { value: CERT_PEM } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: "POST",
        path: "/api/v1/idevid/certificate",
        body: { certificatePem: btoa(CERT_PEM) },
      })
    );
    await waitFor(() => expect(toasts()).toContain("IDevID certificate installed: installed"));
  });

  it("installs the IAK certificate from the pasted PEM", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/iak/certificate": ok({ status: { success: true, message: "installed" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    const text = await screen.findByLabelText("IAK certificate PEM");
    const button = screen.getByRole("button", { name: "Install IAK certificate" }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.change(text, { target: { value: "not a pem" } });
    expect(button.disabled).toBe(true);
    fireEvent.change(text, { target: { value: CERT_PEM } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);

    await waitFor(() =>
      expect(sent).toContainEqual({
        method: "POST",
        path: "/api/v1/idevid/iak/certificate",
        body: { certificatePem: btoa(CERT_PEM) },
      })
    );
    await waitFor(() => expect(toasts()).toContain("IAK certificate installed: installed"));
  });

  it("deletes the IAK certificate after the confirm, and Cancel sends nothing", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "DELETE /api/v1/idevid/iak/certificate": ok({ status: { success: true, message: "deleted" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK certificate" }));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete the IAK certificate?")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.some((r) => r.method === "DELETE")).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Delete IAK certificate" }));
    dialog = await screen.findByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Delete certificate" }));

    await waitFor(() =>
      expect(sent).toContainEqual(
        expect.objectContaining({ method: "DELETE", path: "/api/v1/idevid/iak/certificate" })
      )
    );
    await waitFor(() => expect(toasts()).toContain("IAK certificate deleted: deleted"));
  });

  it("shows a refused install", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/certificate": refused(403, "install denied by policy"),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.change(await screen.findByLabelText("IDevID certificate PEM"), { target: { value: CERT_PEM } });
    fireEvent.click(screen.getByRole("button", { name: "Install IDevID certificate" }));

    await waitFor(() => expect(toasts()).toContain("IDevID certificate install refused: install denied by policy"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "IDevID certificate install refused: install denied by policy");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
  });
});
