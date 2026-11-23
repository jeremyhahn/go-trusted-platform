import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ok, refused, stubControlPlane, withControlPlane } from "@/test/control-plane-fetch";

import TPMQuotePage from "./page";

// The page's controls are gated on the server's capabilities (#2068): this
// server offers every TPM operation the page calls.
const CAPABILITIES = "GET /api/v1/capabilities";
const TPM_OPS = [
  "GET /api/v1/tpm/ak",
  "POST /api/v1/tpm/ak",
  "POST /api/v1/tpm/quote",
  "POST /api/v1/tpm/quote/verify",
];
const CAPS_ON = ok({
  capabilities: TPM_OPS.map((op) => ({ op, kind: "route", enabled: true })),
  total: TPM_OPS.length,
  enabled: TPM_OPS.length,
});

// These tests drive the page through the real SDK client (PlatformProvider),
// with fetch as the only mock. The SDK does not throw on a refusal: it hands
// back `resp.error`, so the page has to look at it.

const QUOTE = "POST /api/v1/tpm/quote";
const VERIFY = "POST /api/v1/tpm/quote/verify";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

async function renderPage() {
  const view = render(withControlPlane(<TPMQuotePage />));
  await screen.findByRole("heading", { level: 1, name: "Quote / Attestation" });
  return view;
}

// The gate holds a control until the server's capabilities have loaded.
async function whenOffered(name: RegExp) {
  await waitFor(() =>
    expect(screen.getByRole("button", { name }).getAttribute("data-capability-enabled")).toBe("true"),
  );
}

async function generateQuote() {
  await whenOffered(/Generate Quote/);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /Generate Quote/ }));
  });
}

async function verifyQuote(container: HTMLElement) {
  const field = (id: string) => {
    const el = container.querySelector(`#${id}`);
    if (!el) throw new Error(`no field #${id}`);
    return el;
  };
  fireEvent.change(field("vquote"), { target: { value: "cXVvdGU=" } });
  fireEvent.change(field("vsig"), { target: { value: "c2ln" } });
  fireEvent.change(field("vnonce"), { target: { value: "00112233" } });
  await whenOffered(/Verify Quote/);
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /Verify Quote/ }));
  });
}

function toasts() {
  return screen.queryAllByTestId("toast");
}

describe("TPMQuotePage refusals on the real SDK client", () => {
  it("posts the quote to /api/v1/tpm/quote through the SDK", async () => {
    const sent = stubControlPlane({ [CAPABILITIES]: CAPS_ON, [QUOTE]: refused(400, "x") });
    await renderPage();
    await generateQuote();

    await waitFor(() => {
      expect(sent.some((r) => r.method === "POST" && r.path === "/api/v1/tpm/quote")).toBe(true);
    });
    const req = sent.find((r) => r.method === "POST" && r.path === "/api/v1/tpm/quote");
    expect(req?.body).toEqual(
      expect.objectContaining({ akHandle: 0x81010002, pcrIndices: [0, 1, 4, 7, 9] }),
    );
  });

  it("shows a refused quote with the server's message, not a binding error", async () => {
    const reason = "tpm: ak handle 0x81010002 not found";
    stubControlPlane({ [CAPABILITIES]: CAPS_ON, [QUOTE]: refused(400, reason) });
    await renderPage();
    await generateQuote();

    const toast = await waitFor(() => {
      const t = toasts().find((el) => el.textContent === `Quote failed: ${reason}`);
      expect(t).toBeDefined();
      return t!;
    });
    expect(toast.getAttribute("data-variant")).toBe("destructive");
    expect(screen.getByText(reason, { selector: "p" })).toBeTruthy();
    expect(screen.queryByText(/no channel binding/)).toBeNull();
  });

  it("shows a refused verify as an error, not an INVALID quote", async () => {
    const reason = "iam: tpm:quote:verify denied";
    stubControlPlane({ [CAPABILITIES]: CAPS_ON, [VERIFY]: refused(403, reason) });
    const { container } = await renderPage();
    await verifyQuote(container);

    const toast = await waitFor(() => {
      const t = toasts().find((el) => el.textContent === `Verify failed: ${reason}`);
      expect(t).toBeDefined();
      return t!;
    });
    expect(toast.getAttribute("data-variant")).toBe("destructive");
    expect(toasts().some((el) => (el.textContent ?? "").startsWith("Quote INVALID"))).toBe(false);
    expect(screen.queryByText("INVALID")).toBeNull();
  });

  it("shows VERIFIED when the server verifies the quote", async () => {
    stubControlPlane({ [CAPABILITIES]: CAPS_ON, [VERIFY]: ok({ verified: true, message: "quote verified" }) });
    const { container } = await renderPage();
    await verifyQuote(container);

    const toast = await waitFor(() => {
      const t = toasts().find((el) => (el.textContent ?? "").startsWith("Quote VERIFIED"));
      expect(t).toBeDefined();
      return t!;
    });
    expect(toast.getAttribute("data-variant")).toBe("success");
    expect(await screen.findByText("VERIFIED")).toBeTruthy();
  });
});
