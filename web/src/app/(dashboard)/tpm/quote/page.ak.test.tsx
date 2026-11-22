import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";

import TPMQuotePage from "./page";

// These tests drive the Attestation Key card through the real SDK client
// (PlatformProvider), with fetch as the only mock. GetAK answers 404 when the
// TPM has no AK: that is the "create one" state, not an error.

const GET_AK = "GET /api/v1/tpm/ak";
const CREATE_AK = "POST /api/v1/tpm/ak";
const AK = { publicKey: "cHVi", handle: 0x81010002, algorithm: "KEY_ALGORITHM_RSA" };

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function renderPage() {
  const view = render(withControlPlane(<TPMQuotePage />));
  await screen.findByRole("heading", { level: 1, name: "Quote / Attestation" });
  return view;
}

function toasts() {
  return screen.queryAllByTestId("toast");
}

async function clickCreateAK() {
  const button = await screen.findByRole("button", { name: /Create AK/ });
  await act(async () => {
    fireEvent.click(button);
  });
}

describe("TPM quote page: attestation key card", () => {
  it("shows the attestation key the server returns", async () => {
    const sent = stubControlPlane({ [GET_AK]: ok(AK) });
    await renderPage();

    expect((await screen.findByTestId("ak-handle")).textContent).toBe("0x81010002");
    expect(screen.getByTestId("ak-algorithm").textContent).toBe("KEY_ALGORITHM_RSA");
    expect(screen.getByTestId("ak-public-key").textContent).toBe("cHVi");
    expect(sent.some((r) => r.method === "GET" && r.path === "/api/v1/tpm/ak")).toBe(true);
    expect(screen.queryByRole("button", { name: /Create AK/ })).toBeNull();
  });

  it("offers Create AK when the server has no AK", async () => {
    stubControlPlane({ [GET_AK]: refused(404, "IAK not found") });
    await renderPage();

    expect(await screen.findByText("No attestation key on this TPM")).toBeTruthy();
    expect(await screen.findByRole("button", { name: /Create AK/ })).toBeTruthy();
    expect(screen.queryByTestId("ak-error")).toBeNull();
    expect(screen.queryByText("IAK not found")).toBeNull();
  });

  it("creates the AK, then reads it again", async () => {
    const routes = {
      [GET_AK]: refused(404, "IAK not found"),
      [CREATE_AK]: ok({ status: { success: true, message: "AK created successfully" }, handle: 0x81010002 }),
    };
    const sent = stubControlPlane(routes);
    await renderPage();

    await screen.findByRole("button", { name: /Create AK/ });
    routes[GET_AK] = ok(AK);
    await clickCreateAK();

    const toast = await waitFor(() => {
      const t = toasts().find((el) => el.textContent === "AK created: AK created successfully");
      expect(t).toBeDefined();
      return t!;
    });
    expect(toast.getAttribute("data-variant")).toBe("success");
    expect((await screen.findByTestId("ak-handle")).textContent).toBe("0x81010002");

    const posts = sent.filter((r) => r.method === "POST" && r.path === "/api/v1/tpm/ak");
    expect(posts).toHaveLength(1);
    const post = posts[0];
    expect(post?.body ?? {}).toEqual({});
    expect(sent.filter((r) => r.method === "GET" && r.path === "/api/v1/tpm/ak")).toHaveLength(2);
    expect(screen.queryByRole("button", { name: /Create AK/ })).toBeNull();
  });

  it("shows a refused create with the server's message", async () => {
    stubControlPlane({
      [GET_AK]: refused(404, "IAK not found"),
      [CREATE_AK]: refused(403, "iam: tpm:ak:create denied"),
    });
    await renderPage();
    // The toast store is module-wide, so an earlier test's toast may still be
    // listed: count the success toasts before the click, not from zero.
    const created = () => toasts().filter((el) => (el.textContent ?? "").startsWith("AK created")).length;
    const createdBefore = created();
    await clickCreateAK();

    const toast = await waitFor(() => {
      const t = toasts().find((el) => el.textContent === "Create AK failed: iam: tpm:ak:create denied");
      expect(t).toBeDefined();
      return t!;
    });
    expect(toast.getAttribute("data-variant")).toBe("destructive");
    expect(created()).toBeLessThanOrEqual(createdBefore);
    expect(screen.getByRole("button", { name: /Create AK/ })).toBeTruthy();
    expect(screen.queryByTestId("ak-handle")).toBeNull();
  });

  it("shows a refused read as an error, without Create AK", async () => {
    stubControlPlane({ [GET_AK]: refused(403, "iam: tpm:ak:read denied") });
    await renderPage();

    expect((await screen.findByTestId("ak-error")).textContent).toBe("iam: tpm:ak:read denied");
    expect(screen.queryByRole("button", { name: /Create AK/ })).toBeNull();
    expect(screen.queryByText("No attestation key on this TPM")).toBeNull();
  });
});
