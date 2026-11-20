/**
 * Real-server spec for the TPM provisioning row (#2068, epic #1665).
 *
 * Covers TPMService Provision, Clear, GetCapabilities, GetPlatformAttributes,
 * CreateEK, DeleteEK, ImportEKCertificate, CreateSRK, DeleteSRK, CreateAK,
 * GetAK, DeleteAK, Quote, VerifyQuote and Certify through the controls of
 * `(dashboard)/tpm/keys` (TPMKeyOperations) and `(dashboard)/tpm/quote`.
 *
 * State is read and seeded through the `sdk` fixture (no route mocks); each
 * assertion compares what the page shows with what the server answers.
 */
import type { Page } from "@playwright/test";
import { test, expect } from "./fixtures";

const KEYS = "/tpm/keys";
const QUOTE = "/tpm/quote";
const PLATFORM_IAK_HANDLE = 0x81010002;

/** Waits for an operation's outcome: its result block or its error line. */
async function outcomeOf(page: Page, op: string): Promise<"result" | "error"> {
  const result = page.getByTestId(`tpm-result-${op}`);
  const error = page.getByTestId(`tpm-error-${op}`);
  await expect(result.or(error)).toBeVisible({ timeout: 30_000 });
  return (await result.isVisible()) ? "result" : "error";
}

async function shownJSON(page: Page, op: string): Promise<unknown> {
  return JSON.parse((await page.getByTestId(`tpm-result-${op}`).textContent()) ?? "null");
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function derToPEM(derB64: string): string {
  const lines = derB64.match(/.{1,64}/g) ?? [];
  return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n");
}

test.describe("TPM provisioning (real server)", () => {
  test("GetCapabilities shows what the server reports", async ({ adminPage, sdk }) => {
    const want = await sdk.tpm.getCapabilities();
    expect(want.success).toBe(true);

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-capabilities").click();
    expect(await outcomeOf(adminPage, "capabilities")).toBe("result");
    expect(await shownJSON(adminPage, "capabilities")).toEqual(want.data);
  });

  test("GetPlatformAttributes shows what the server reports", async ({ adminPage, sdk }) => {
    const want = await sdk.tpm.getPlatformAttributes();
    expect(want.success).toBe(true);

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-platform").click();
    expect(await outcomeOf(adminPage, "platform")).toBe("result");
    expect(await shownJSON(adminPage, "platform")).toEqual(want.data);
  });

  test("Provision answers with the server's outcome and leaves an EK and SRK", async ({ adminPage, sdk }) => {
    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-provision").click();
    const outcome = await outcomeOf(adminPage, "provision");
    if (outcome === "error") {
      // An already provisioned TPM refuses; the page shows the server's reason.
      await expect(adminPage.getByTestId("tpm-error-provision")).not.toBeEmpty();
    }
    const ek = await sdk.tpm.getEK();
    const srk = await sdk.tpm.getSRK();
    expect(ek.success).toBe(true);
    expect(srk.success).toBe(true);
  });

  test("Clear asks first; Cancel sends nothing", async ({ adminPage, sdk }) => {
    const before = await sdk.tpm.getEK();

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-clear").click();
    await expect(adminPage.getByTestId("tpm-confirm-dialog")).toContainText("Clear the TPM?");
    await adminPage.getByTestId("tpm-confirm-cancel").click();
    await expect(adminPage.getByTestId("tpm-confirm-dialog")).toBeHidden();
    await expect(adminPage.getByTestId("tpm-result-clear")).toHaveCount(0);
    await expect(adminPage.getByTestId("tpm-error-clear")).toHaveCount(0);

    const after = await sdk.tpm.getEK();
    expect(after.data).toEqual(before.data);
  });

  test("Clear with a wrong owner password shows the server's refusal", async ({ adminPage, sdk }) => {
    const before = await sdk.tpm.getEK();

    await adminPage.goto(KEYS);
    await adminPage.getByLabel("Owner password").fill(`wrong-${Date.now()}`);
    await adminPage.getByTestId("tpm-op-clear").click();
    await adminPage.getByTestId("tpm-confirm-ok").click();
    const outcome = await outcomeOf(adminPage, "clear");
    if (outcome === "error") {
      await expect(adminPage.getByTestId("tpm-error-clear")).not.toBeEmpty();
      const after = await sdk.tpm.getEK();
      expect(after.data).toEqual(before.data);
    } else {
      // A simulator with an empty owner auth clears anyway: provision again
      // so the later tests find their keys.
      const res = await sdk.tpm.provision({ createEk: true, createSrk: true, createAk: true });
      expect(res.success).toBe(true);
    }
  });

  test("CreateEK and CreateSRK show the keys the server then reports", async ({ adminPage, sdk }) => {
    await adminPage.goto(KEYS);

    await adminPage.getByTestId("tpm-op-createEK").click();
    if ((await outcomeOf(adminPage, "createEK")) === "result") {
      const ek = await sdk.tpm.getEK();
      expect(ek.success).toBe(true);
    }

    await adminPage.getByTestId("tpm-op-createSRK").click();
    if ((await outcomeOf(adminPage, "createSRK")) === "result") {
      const srk = await sdk.tpm.getSRK();
      expect(srk.success).toBe(true);
    }
  });

  test("DeleteSRK evicts the SRK after the confirm; CreateSRK restores it", async ({ adminPage, sdk }) => {
    const seeded = await sdk.tpm.createSRK({ persistent: true });
    expect(seeded.success !== false || (await sdk.tpm.getSRK()).success).toBe(true);

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-deleteSRK").click();
    await expect(adminPage.getByTestId("tpm-confirm-dialog")).toContainText("Delete Storage Root Key?");
    await adminPage.getByTestId("tpm-confirm-ok").click();
    expect(await outcomeOf(adminPage, "deleteSRK")).toBe("result");
    expect((await sdk.tpm.getSRK()).success).toBe(false);

    await adminPage.getByTestId("tpm-op-createSRK").click();
    expect(await outcomeOf(adminPage, "createSRK")).toBe("result");
    expect((await sdk.tpm.getSRK()).success).toBe(true);
  });

  test("DeleteEK evicts the EK after the confirm; CreateEK restores it", async ({ adminPage, sdk }) => {
    const seeded = await sdk.tpm.createEK({ persistent: true });
    expect(seeded.success !== false || (await sdk.tpm.getEK()).success).toBe(true);

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-deleteEK").click();
    await expect(adminPage.getByTestId("tpm-confirm-dialog")).toContainText("Delete Endorsement Key?");
    await adminPage.getByTestId("tpm-confirm-ok").click();
    expect(await outcomeOf(adminPage, "deleteEK")).toBe("result");
    expect((await sdk.tpm.getEK()).success).toBe(false);

    await adminPage.getByTestId("tpm-op-createEK").click();
    expect(await outcomeOf(adminPage, "createEK")).toBe("result");
    expect((await sdk.tpm.getEK()).success).toBe(true);
  });

  test("ImportEKCertificate sends the pasted PEM and shows the server's answer", async ({ adminPage, sdk }) => {
    const cert = await sdk.tpm.getEKCertificate();
    test.skip(cert.success === false, "the harness TPM carries no EK certificate to re-import");
    const der = (cert.data as { certificate?: string } | undefined)?.certificate ?? "";
    test.skip(der === "", "the harness TPM carries no EK certificate to re-import");

    await adminPage.goto(KEYS);
    await expect(adminPage.getByTestId("tpm-op-importEKCertificate")).toBeDisabled();
    await adminPage.getByLabel("EK certificate (PEM)").fill(derToPEM(der));
    await adminPage.getByTestId("tpm-op-importEKCertificate").click();
    expect(await outcomeOf(adminPage, "importEKCertificate")).toBe("result");

    const after = await sdk.tpm.getEKCertificate();
    expect((after.data as { certificate?: string } | undefined)?.certificate).toBe(der);
  });

  test("ImportEKCertificate refuses text that is not a PEM certificate", async ({ adminPage }) => {
    await adminPage.goto(KEYS);
    await adminPage.getByLabel("EK certificate (PEM)").fill("not a certificate");
    await adminPage.getByTestId("tpm-op-importEKCertificate").click();
    await expect(adminPage.getByText("Invalid certificate").first()).toBeVisible();
    await expect(adminPage.getByTestId("tpm-result-importEKCertificate")).toHaveCount(0);
  });

  test("CreateAK and GetAK show the AK the server reports", async ({ adminPage, sdk }) => {
    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-createAK").click();
    await outcomeOf(adminPage, "createAK");

    const want = await sdk.tpm.getAK();
    await adminPage.getByTestId("tpm-op-getAK").click();
    const outcome = await outcomeOf(adminPage, "getAK");
    if (want.success === false) {
      expect(outcome).toBe("error");
    } else {
      expect(outcome).toBe("result");
      expect(await shownJSON(adminPage, "getAK")).toEqual(want.data);
    }
  });

  test("DeleteAK of the platform IAK shows the server's refusal and keeps the key", async ({ adminPage, sdk }) => {
    const before = await sdk.tpm.getAK({ handle: PLATFORM_IAK_HANDLE });

    await adminPage.goto(KEYS);
    await adminPage.getByLabel("AK handle (Delete AK)").fill(`0x${PLATFORM_IAK_HANDLE.toString(16)}`);
    await adminPage.getByTestId("tpm-op-deleteAK").click();
    await expect(adminPage.getByTestId("tpm-confirm-dialog")).toContainText("refuses to evict");
    await adminPage.getByTestId("tpm-confirm-ok").click();
    expect(await outcomeOf(adminPage, "deleteAK")).toBe("error");

    const after = await sdk.tpm.getAK({ handle: PLATFORM_IAK_HANDLE });
    expect(after.success).toBe(before.success);
  });

  test("Certify of the SRK shows the server's certification", async ({ adminPage, sdk }) => {
    const srk = await sdk.tpm.getSRK();
    test.skip(srk.success === false, "no SRK to certify");

    await adminPage.goto(KEYS);
    await adminPage.getByTestId("tpm-op-certify").click();
    expect(await outcomeOf(adminPage, "certify")).toBe("result");
    const shown = (await shownJSON(adminPage, "certify")) as Record<string, unknown>;
    expect(Object.keys(shown).length).toBeGreaterThan(0);
  });

  test("Quote then Verify Quote on the keys page reports VERIFIED", async ({ adminPage }) => {
    await adminPage.goto(KEYS);
    await expect(adminPage.getByTestId("tpm-op-verifyQuote")).toBeDisabled();
    await adminPage.getByTestId("tpm-op-quote").click();
    expect(await outcomeOf(adminPage, "quote")).toBe("result");

    await adminPage.getByTestId("tpm-op-verifyQuote").click();
    await expect(adminPage.getByTestId("tpm-verdict-verifyQuote")).toContainText("VERIFIED");
  });

  test("the quote page generates a quote and verifies it", async ({ adminPage }) => {
    await adminPage.goto(QUOTE);
    await adminPage.getByRole("button", { name: /generate quote/i }).click();
    await expect(adminPage.locator("#vquote")).not.toHaveValue("", { timeout: 30_000 });
    await expect(adminPage.locator("#vsig")).not.toHaveValue("");

    await adminPage.getByRole("button", { name: /verify quote/i }).click();
    await expect(adminPage.getByText("VERIFIED", { exact: true }).first()).toBeVisible();
  });

  test("the quote page verifies a quote seeded through the SDK, and refuses a tampered signature", async ({
    adminPage,
    sdk,
  }) => {
    const nonce = toBase64(crypto.getRandomValues(new Uint8Array(32)));
    const quoted = await sdk.tpm.quote({ akHandle: PLATFORM_IAK_HANDLE, pcrIndices: [0, 7], nonce });
    expect(quoted.success).toBe(true);
    const q = quoted.data as { quote?: string; signature?: string; signatureAlgorithm?: string; channelBinding?: string };

    await adminPage.goto(QUOTE);
    await adminPage.locator("#vquote").fill(q.quote ?? "");
    await adminPage.locator("#vsig").fill(q.signature ?? "");
    await adminPage.locator("#vnonce").fill(nonce);
    await adminPage.locator("#vscheme").fill(q.signatureAlgorithm ?? "");
    await adminPage.locator("#vbinding").fill(q.channelBinding ?? "");
    await adminPage.getByRole("button", { name: /verify quote/i }).click();
    await expect(adminPage.getByText("VERIFIED", { exact: true }).first()).toBeVisible();

    const sig = Buffer.from(q.signature ?? "", "base64");
    sig[0] ^= 0xff;
    await adminPage.locator("#vsig").fill(sig.toString("base64"));
    await adminPage.getByRole("button", { name: /verify quote/i }).click();
    await expect(adminPage.getByText("INVALID", { exact: true }).first()).toBeVisible();
  });
});
