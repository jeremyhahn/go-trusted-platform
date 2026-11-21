import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page generates the IAK (GenerateIAK) and, after a
// confirm, asks the IDevID service to delete it (DeleteIAK), through the
// real SDK client over a stubbed fetch, and re-reads HasIAK after each.

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

const toasts = () => screen.queryAllByTestId("toast").map((t) => t.textContent);

describe("TPMStatusPage IAK generate and delete", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("generates the IAK and re-reads HasIAK", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "POST /api/v1/idevid/iak/generate": ok({ status: { success: true, message: "IAK generated successfully" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("No IAK");
    routes["GET /api/v1/idevid/iak/exists"] = ok({ exists: true });
    fireEvent.click(await screen.findByRole("button", { name: "Generate IAK" }));

    expect(await screen.findByText("IAK Present")).toBeTruthy();
    expect(sent).toContainEqual(expect.objectContaining({ method: "POST", path: "/api/v1/idevid/iak/generate" }));
    await waitFor(() => expect(toasts()).toContain("IAK generated: IAK generated successfully"));
    expect(
      sent.filter((r) => r.method === "GET" && r.path === "/api/v1/idevid/iak/exists").length
    ).toBeGreaterThanOrEqual(2);
  });

  it("shows a refused GenerateIAK and keeps the IAK absent", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "POST /api/v1/idevid/iak/generate": refused(403, "permission denied"),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("No IAK");
    fireEvent.click(await screen.findByRole("button", { name: "Generate IAK" }));

    await waitFor(() => expect(toasts()).toContain("IAK generation failed: permission denied"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "IAK generation failed: permission denied");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
    expect(screen.getByText("No IAK")).toBeTruthy();
  });

  it("asks before deleting the IAK, and Cancel sends nothing", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("IAK Present");
    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Delete the IAK?")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.some((r) => r.method === "DELETE")).toBe(false);
  });

  it("deletes the IAK after the confirm and re-reads HasIAK", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
      "DELETE /api/v1/idevid/iak": ok({ status: { success: true, message: "IAK deleted" } }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("IAK Present");
    routes["GET /api/v1/idevid/iak/exists"] = ok({ exists: false });
    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete IAK" }));

    expect(await screen.findByText("No IAK")).toBeTruthy();
    expect(sent).toContainEqual(expect.objectContaining({ method: "DELETE", path: "/api/v1/idevid/iak" }));
    await waitFor(() => expect(toasts()).toContain("IAK deleted: IAK deleted"));
  });

  it("shows the service's refusal of DeleteIAK", async () => {
    const refusal = "the IAK key is TPM-resident and is not evicted by this service";
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
      "DELETE /api/v1/idevid/iak": refused(403, refusal),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("IAK Present");
    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete IAK" }));

    await waitFor(() => expect(toasts()).toContain(`IAK delete refused: ${refusal}`));
    expect(screen.getByText("IAK Present")).toBeTruthy();
  });
});
