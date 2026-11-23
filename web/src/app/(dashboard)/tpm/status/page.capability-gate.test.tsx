import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page's IDevID write controls follow the server's
// capabilities: Generate IAK, Delete IAK, Flush transient contexts, Install
// IDevID certificate, Install IAK certificate and Delete IAK certificate are
// each wrapped in the capability gate, so a server that does not offer the
// operation leaves the control disabled with the server's reason as its title.

const IDEVID_OPS = [
  "POST /api/v1/idevid/iak/generate",
  "DELETE /api/v1/idevid/iak",
  "POST /api/v1/idevid/flush",
  "POST /api/v1/idevid/certificate",
  "POST /api/v1/idevid/iak/certificate",
  "DELETE /api/v1/idevid/iak/certificate",
];

const REASON = "not-configured: idevid";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";

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

const iakInfo = { keyInfo: { keyType: "IAK" } };

function caps(off: string[] = []): Answer {
  const capabilities = IDEVID_OPS.map((op) =>
    off.includes(op) ? { op, kind: "route", enabled: false, reason: REASON } : { op, kind: "route", enabled: true },
  );
  return ok({ capabilities, total: capabilities.length, enabled: capabilities.filter((c) => c.enabled).length });
}

function button(name: string): HTMLButtonElement {
  if (name === "Delete IAK") {
    return within(screen.getByTestId("iak-actions")).getByRole("button", { name }) as HTMLButtonElement;
  }
  return screen.getByRole("button", { name }) as HTMLButtonElement;
}

async function expectWithheld(name: string) {
  await waitFor(() => expect(button(name).getAttribute("title")).toBe(REASON));
  expect(button(name).disabled).toBe(true);
  expect(button(name).getAttribute("data-capability-enabled")).toBe("false");
}

function routes(capabilities: Answer): Record<string, Answer> {
  return {
    "GET /api/v1/tpm/info": ok(tpmInfo),
    "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
    "GET /api/v1/idevid/iak": ok(iakInfo),
    "POST /api/v1/idevid/iak/generate": ok({ status: { success: true, message: "IAK generated successfully" } }),
    "GET /api/v1/capabilities": capabilities,
  };
}

describe("TPMStatusPage IDevID capability gate", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("withholds every IDevID write control when the server offers none of them", async () => {
    const sent = stubControlPlane(routes(caps(IDEVID_OPS)));
    render(withControlPlane(<TPMStatusPage />));

    await screen.findByRole("button", { name: "Generate IAK" });
    await expectWithheld("Generate IAK");
    await expectWithheld("Delete IAK");
    await expectWithheld("Flush transient contexts");
    await expectWithheld("Delete IAK certificate");

    fireEvent.change(screen.getByLabelText("IDevID certificate PEM"), { target: { value: PEM } });
    fireEvent.change(screen.getByLabelText("IAK certificate PEM"), { target: { value: PEM } });
    await expectWithheld("Install IDevID certificate");
    await expectWithheld("Install IAK certificate");

    fireEvent.click(button("Generate IAK"));
    expect(sent).not.toContainEqual(expect.objectContaining({ method: "POST", path: "/api/v1/idevid/iak/generate" }));
  });

  it("enables every IDevID write control the server offers", async () => {
    stubControlPlane(routes(caps()));
    render(withControlPlane(<TPMStatusPage />));

    await screen.findByRole("button", { name: "Generate IAK" });
    for (const name of [
      "Generate IAK",
      "Delete IAK",
      "Flush transient contexts",
      "Install IDevID certificate",
      "Install IAK certificate",
      "Delete IAK certificate",
    ]) {
      await waitFor(() => expect(button(name).getAttribute("data-capability-enabled")).toBe("true"));
    }
    expect(button("Generate IAK").disabled).toBe(false);
  });
});
