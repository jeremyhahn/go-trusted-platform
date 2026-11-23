import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page mounts the LDevID and Activate credential cards,
// so Create LDevID and Activate credential are reachable from /tpm/status;
// Delete IAK certificate stays a single control, the page's own.

const capsOn = ok({
  capabilities: [
    "POST /api/v1/idevid/iak/generate",
    "DELETE /api/v1/idevid/iak",
    "POST /api/v1/idevid/flush",
    "POST /api/v1/idevid/certificate",
    "POST /api/v1/idevid/iak/certificate",
    "DELETE /api/v1/idevid/iak/certificate",
    "POST /api/v1/idevid/ldevid",
    "POST /api/v1/idevid/activate-credential",
  ].map((op) => ({ op, kind: "route", enabled: true })),
  total: 8,
  enabled: 8,
});

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

describe("TPMStatusPage IDevID cards", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("mounts the LDevID and Activate credential cards", async () => {
    stubControlPlane({ "GET /api/v1/tpm/info": ok(tpmInfo), "GET /api/v1/capabilities": capsOn });
    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByTestId("ldevid-card")).toBeTruthy();
    expect(screen.getByTestId("iak-cert-actions-card")).toBeTruthy();
    expect(screen.getAllByRole("button", { name: "Delete IAK certificate" })).toHaveLength(1);
  });

  it("creates an LDevID from the status page", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "POST /api/v1/idevid/ldevid": ok({ status: { success: true, message: "issued" } }),
    };
    const sent = stubControlPlane(routes);
    render(withControlPlane(<TPMStatusPage />));

    const card = within(await screen.findByTestId("ldevid-card"));
    fireEvent.change(card.getByLabelText("Common name"), { target: { value: "device-01.example" } });
    const create = card.getByRole("button", { name: "Create LDevID" }) as HTMLButtonElement;
    await waitFor(() => expect(create.getAttribute("data-capability-enabled")).toBe("true"));
    fireEvent.click(create);

    await waitFor(() =>
      expect(sent).toContainEqual(
        expect.objectContaining({
          method: "POST",
          path: "/api/v1/idevid/ldevid",
          body: expect.objectContaining({ template: expect.objectContaining({ commonName: "device-01.example" }) }),
        }),
      ),
    );
  });
});
