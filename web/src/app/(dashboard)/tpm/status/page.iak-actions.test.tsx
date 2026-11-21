import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  ok,
  refused,
  stubControlPlane,
  withControlPlane,
  type Answer,
  type SentRequest,
} from "@/test/control-plane-fetch";
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

const iakInfo = { keyInfo: { keyType: "IAK" } };

const toasts = () => screen.queryAllByTestId("toast").map((t) => t.textContent);

// readsAfter counts the HasIAK (GET /api/v1/idevid/iak/exists) and IAK-info
// (GET /api/v1/idevid/iak) reads recorded after the last `method path`
// request, the mutation. It answers -1 for both when the mutation was not sent.
const readsAfter = (sent: SentRequest[], method: string, path: string) => {
  let at = -1;
  sent.forEach((r, i) => {
    if (r.method === method && r.path === path) at = i;
  });
  if (at < 0) return { exists: -1, info: -1 };
  const gets = sent.slice(at + 1).filter((r) => r.method === "GET");
  return {
    exists: gets.filter((r) => r.path === "/api/v1/idevid/iak/exists").length,
    info: gets.filter((r) => r.path === "/api/v1/idevid/iak").length,
  };
};

describe("TPMStatusPage IAK generate and delete", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("generates the IAK and re-reads HasIAK", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
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
    await waitFor(() => expect(readsAfter(sent, "POST", "/api/v1/idevid/iak/generate")).toEqual({ exists: 1, info: 1 }));
  });

  it("shows a refused GenerateIAK and keeps the IAK absent", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
      "POST /api/v1/idevid/iak/generate": refused(403, "permission denied"),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("No IAK");
    fireEvent.click(await screen.findByRole("button", { name: "Generate IAK" }));

    await waitFor(() => expect(toasts()).toContain("IAK generation failed: permission denied"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "IAK generation failed: permission denied");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
    expect(screen.getByText("No IAK")).toBeTruthy();
    await waitFor(() => expect(readsAfter(sent, "POST", "/api/v1/idevid/iak/generate")).toEqual({ exists: 1, info: 1 }));
  });

  it("asks before deleting the IAK, and Cancel sends nothing", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
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
      "GET /api/v1/idevid/iak": ok(iakInfo),
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
    await waitFor(() => expect(readsAfter(sent, "DELETE", "/api/v1/idevid/iak")).toEqual({ exists: 1, info: 1 }));
  });

  it("shows the service's refusal of DeleteIAK", async () => {
    const refusal = "the IAK key is TPM-resident and is not evicted by this service";
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
      "DELETE /api/v1/idevid/iak": refused(403, refusal),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("IAK Present");
    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete IAK" }));

    await waitFor(() => expect(toasts()).toContain(`IAK delete refused: ${refusal}`));
    expect(screen.getByText("IAK Present")).toBeTruthy();
    await waitFor(() => expect(readsAfter(sent, "DELETE", "/api/v1/idevid/iak")).toEqual({ exists: 1, info: 1 }));
  });

  it("shows an IAK present after a failed GenerateIAK that left one", async () => {
    const failure = "IAK created but its attributes were not stored";
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
      "POST /api/v1/idevid/iak/generate": refused(500, failure),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("No IAK");
    routes["GET /api/v1/idevid/iak/exists"] = ok({ exists: true });
    fireEvent.click(await screen.findByRole("button", { name: "Generate IAK" }));

    await waitFor(() => expect(toasts()).toContain(`IAK generation failed: ${failure}`));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === `IAK generation failed: ${failure}`);
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
    expect(await screen.findByText("IAK Present")).toBeTruthy();
    await waitFor(() => expect(readsAfter(sent, "POST", "/api/v1/idevid/iak/generate")).toEqual({ exists: 1, info: 1 }));
  });

  it("shows No IAK after a refused DeleteIAK whose re-read finds none", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: true }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
      "DELETE /api/v1/idevid/iak": refused(403, "permission denied"),
    };
    const sent = stubControlPlane(routes);

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("IAK Present");
    fireEvent.click(await screen.findByRole("button", { name: "Delete IAK" }));
    routes["GET /api/v1/idevid/iak/exists"] = ok({ exists: false });
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete IAK" }));

    await waitFor(() => expect(toasts()).toContain("IAK delete refused: permission denied"));
    const toast = screen
      .getAllByTestId("toast")
      .find((t) => t.textContent === "IAK delete refused: permission denied");
    expect(toast?.getAttribute("data-variant")).toBe("destructive");
    expect(await screen.findByText("No IAK")).toBeTruthy();
    await waitFor(() => expect(readsAfter(sent, "DELETE", "/api/v1/idevid/iak")).toEqual({ exists: 1, info: 1 }));
  });

  it("keeps the IAK buttons disabled until the HasIAK re-read answers", async () => {
    const routes: Record<string, Answer> = {
      "GET /api/v1/tpm/info": ok(tpmInfo),
      "GET /api/v1/idevid/iak/exists": ok({ exists: false }),
      "GET /api/v1/idevid/iak": ok(iakInfo),
      "POST /api/v1/idevid/iak/generate": ok({ status: { success: true, message: "IAK generated successfully" } }),
    };
    const sent = stubControlPlane(routes);
    const routed = globalThis.fetch;
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let posted = false;
    // Once the POST has gone, hold the HasIAK re-read until release().
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      const method = (init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
      if (method === "POST") posted = true;
      else if (posted && method === "GET" && url.pathname === "/api/v1/idevid/iak/exists") await gate;
      return routed(input, init);
    });

    render(withControlPlane(<TPMStatusPage />));

    await screen.findByText("No IAK");
    routes["GET /api/v1/idevid/iak/exists"] = ok({ exists: true });
    fireEvent.click(await screen.findByRole("button", { name: "Generate IAK" }));

    await waitFor(() => expect(toasts()).toContain("IAK generated: IAK generated successfully"));
    const generate = screen.getByRole("button", { name: "Generate IAK" }) as HTMLButtonElement;
    const remove = screen.getByRole("button", { name: "Delete IAK" }) as HTMLButtonElement;
    expect(generate.disabled).toBe(true);
    expect(remove.disabled).toBe(true);
    expect(screen.getByText("No IAK")).toBeTruthy();

    release();
    expect(await screen.findByText("IAK Present")).toBeTruthy();
    await waitFor(() => expect(generate.disabled).toBe(false));
    await waitFor(() => expect(readsAfter(sent, "POST", "/api/v1/idevid/iak/generate")).toEqual({ exists: 1, info: 1 }));
  });
});
