import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane, type Answer } from "@/test/control-plane-fetch";
import TPMStatusPage from "./page";

// #2055: the TPM status page, after a confirm, asks the IDevID service to
// flush every transient TPM context (FlushTransientContexts), through the
// real SDK client over a stubbed fetch, and shows the answer or the refusal.

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

describe("TPMStatusPage flush transient contexts", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("flushes the transient contexts after the confirm", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/flush": ok({
        status: { success: true, message: "flushed 3 transient context(s)" },
        flushedCount: 3,
      }),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.click(await screen.findByRole("button", { name: "Flush transient contexts" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Flush the transient contexts?")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Flush" }));

    await waitFor(() =>
      expect(sent).toContainEqual(expect.objectContaining({ method: "POST", path: "/api/v1/idevid/flush" }))
    );
    await waitFor(() => expect(toasts()).toContain("Transient contexts flushed: flushed 3 transient context(s)"));
  });

  it("asks before flushing, and Cancel sends nothing", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.click(await screen.findByRole("button", { name: "Flush transient contexts" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Flush the transient contexts?")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(sent.some((r) => r.path === "/api/v1/idevid/flush")).toBe(false);
  });

  it("shows a refused flush", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "POST /api/v1/idevid/flush": refused(403, "flush denied by policy"),
    };
    stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    fireEvent.click(await screen.findByRole("button", { name: "Flush transient contexts" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Flush" }));

    await waitFor(() => expect(toasts()).toContain("Flush refused: flush denied by policy"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "Flush refused: flush denied by policy");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
  });
});
