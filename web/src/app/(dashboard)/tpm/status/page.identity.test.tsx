import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { type Answer, ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page asks the IDevID service directly whether the
// IDevID and the IAK exist (HasIDevID, HasIAK) and shows the TCG device
// attributes (GetDeviceAttributes), through the real SDK client over a
// stubbed fetch, the same boundary the browser crosses.

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

describe("TPMStatusPage identity keys and device attributes", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("shows IDevID and IAK presence from HasIDevID and HasIAK", async () => {
    const sent = stubControlPlane({
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "GET /api/v1/idevid/iak": ok({ keyInfo: { handle: 2164260865 } }),
    });

    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByText("IDevID Present")).toBeTruthy();
    expect(await screen.findByText("No IAK")).toBeTruthy();
    expect(sent).toContainEqual({ method: "GET", path: "/api/v1/idevid/exists", body: undefined });
    expect(sent).toContainEqual({ method: "GET", path: "/api/v1/idevid/iak/exists", body: undefined });
  });

  it("shows a refused HasIDevID as Unknown, not as absent", async () => {
    stubControlPlane({
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/exists": refused(503, "idevid service is not available"),
    });

    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByText("IDevID Unknown")).toBeTruthy();
    expect(screen.queryByText("No IDevID")).toBeNull();
  });

  // #2170 Codex: useApi keeps the last data when a fetch fails, so a refused
  // refresh must not leave the earlier answer on screen as if it were current.
  it("a failed HasIDevID refresh shows IDevID Unknown, not the old Present", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByText("IDevID Present")).toBeTruthy();
    expect(await screen.findByText("IAK Present")).toBeTruthy();

    routes["GET /api/v1/idevid/exists"] = refused(403, "permission denied");
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("IDevID Unknown")).toBeTruthy();
    expect(screen.queryByText("IDevID Present")).toBeNull();
    expect(screen.getByText("IAK Present")).toBeTruthy();
  });

  it("a failed HasIAK refresh shows IAK Unknown, not the old No IAK", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByText("No IAK")).toBeTruthy();
    expect(await screen.findByText("IDevID Present")).toBeTruthy();

    routes["GET /api/v1/idevid/iak/exists"] = refused(403, "permission denied");
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("IAK Unknown")).toBeTruthy();
    expect(screen.queryByText("No IAK")).toBeNull();
    expect(screen.getByText("IDevID Present")).toBeTruthy();
  });

  it("shows the TCG device attributes", async () => {
    stubControlPlane({
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/attributes": ok({
        attributes: {
          tpmManufacturer: "IFX",
          tpmModel: "SLB9672",
          tpmVersion: "16.13",
          platformManufacturer: "Acme",
          platformModel: "Edge 1",
          platformVersion: "2",
          platformSerial: "SN-0042",
        },
      }),
    });

    render(withControlPlane(<TPMStatusPage />));

    const card = within(await screen.findByTestId("device-attributes"));
    expect(card.getByText("TPM Manufacturer")).toBeTruthy();
    expect(card.getByText("Platform Serial")).toBeTruthy();
    for (const value of ["IFX", "SLB9672", "16.13", "Acme", "Edge 1", "2", "SN-0042"]) {
      expect(await card.findByText(value)).toBeTruthy();
    }
  });

  it("says why the device attributes are unavailable", async () => {
    stubControlPlane({
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/capabilities": capsOn,
      "GET /api/v1/idevid/attributes": refused(403, "permission denied"),
    });

    render(withControlPlane(<TPMStatusPage />));

    expect(await screen.findByText("Device attributes unavailable: permission denied")).toBeTruthy();
  });
});
