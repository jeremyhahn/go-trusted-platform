import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page installs the IDevID and IAK certificates and,
// after a confirm, deletes the IAK certificate through the IDevID service
// (useIDevIDCerts), over a stubbed fetch, and shows the answer or the refusal.
// It offers no IAK CSR control until the server returns a usable CSR.

// The page's IDevID write controls are capability-gated (#2055): the server
// offers all six here.
const capsOn = ok({
  capabilities: [
    "POST /api/v1/idevid/iak/generate",
    "DELETE /api/v1/idevid/iak",
    "POST /api/v1/idevid/flush",
    "POST /api/v1/idevid/certificate",
    "POST /api/v1/idevid/iak/certificate",
    "DELETE /api/v1/idevid/iak/certificate",
  ].map((op) => ({ op, kind: "route", enabled: true })),
  total: 6,
  enabled: 6,
});

// enabledButton waits for the capabilities answer to enable a gated control
// before the test clicks it.
async function enabledButton(name: string): Promise<HTMLElement> {
  const control = await screen.findByRole("button", { name });
  await waitFor(() => expect(control.getAttribute("data-capability-enabled")).toBe("true"));
  return control;
}

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

const CERT_PEM = "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----";

const toasts = () => screen.queryAllByTestId("toast").map((t) => t.textContent);

describe("TPMStatusPage identity certificates (#2055)", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("offers no IAK CSR control while the server cannot produce a CSR", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByTestId("identity-certificates");
    expect(screen.queryByRole("button", { name: "Create IAK CSR" })).toBeNull();
    expect(screen.queryByLabelText("IAK CSR common name")).toBeNull();
    expect(sent.some((s) => s.path === "/api/v1/idevid/iak/csr")).toBe(false);
  });

  it("installs the IDevID certificate from the pasted PEM", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
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
      "GET /api/v1/capabilities": capsOn,
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
      "GET /api/v1/capabilities": capsOn,
      "DELETE /api/v1/idevid/iak/certificate": ok({ status: { success: true, message: "deleted" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.click(await enabledButton("Delete IAK certificate"));
    let dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete the IAK certificate?")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.some((r) => r.method === "DELETE")).toBe(false);

    fireEvent.click(await enabledButton("Delete IAK certificate"));
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
      "GET /api/v1/capabilities": capsOn,
      "POST /api/v1/idevid/certificate": refused(403, "install denied by policy"),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.change(await screen.findByLabelText("IDevID certificate PEM"), { target: { value: CERT_PEM } });
    fireEvent.click(await enabledButton("Install IDevID certificate"));

    await waitFor(() => expect(toasts()).toContain("IDevID certificate install refused: install denied by policy"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "IDevID certificate install refused: install denied by policy");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
  });
});
