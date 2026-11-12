import { test, expect, Page } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
import { mockKmsOpsApi } from "./fixtures/api-mock";

// KMS operations page (#1734, slice 20 of #1665): one test per REST operation.

const b64 = (s: string) => Buffer.from(s, "utf8").toString("base64");

async function openPage(page: Page, config?: Parameters<typeof mockKmsOpsApi>[1]) {
  const mock = await mockKmsOpsApi(page, config);
  await page.goto("/kms/operations");
  await expect(page.getByRole("heading", { name: "KMS Operations" })).toBeVisible();
  return mock;
}

test.describe("KMS operations", () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test("imports a key", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-import");
    await card.getByLabel("Key name").fill("imported");
    await card.getByLabel("Algorithm").fill("aes-256-gcm");
    await card.getByLabel("Key material (base64)").fill(b64("material"));
    await card.getByRole("button", { name: "Import" }).click();
    await expect(page.getByTestId("import-result")).toHaveText("Imported imported v1 (aes-256-gcm)");
    const call = mock.calls.find((c) => c.path === "/keys/import");
    expect(call?.method).toBe("POST");
    expect(call?.body).toMatchObject({ name: "imported", key_material: b64("material") });
  });

  test("updates key status behind a confirm dialog", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-status");
    await card.getByLabel("Key name").fill("k1");
    await card.getByLabel("New status").selectOption("DISABLED");
    await card.getByRole("button", { name: "Update status" }).click();

    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Set k1 to DISABLED?");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();
    expect(mock.calls.some((c) => c.path === "/keys/k1/status")).toBe(false);

    await card.getByRole("button", { name: "Update status" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Confirm" }).click();
    await expect(page.getByTestId("status-result")).toHaveText("k1 v2 is DISABLED");
    const call = mock.calls.find((c) => c.path === "/keys/k1/status");
    expect(call?.method).toBe("PUT");
    expect(call?.body).toEqual({ status: "DISABLED" });
  });

  test("offers only the statuses the KMS service accepts", async ({ page }) => {
    await openPage(page);
    const card = page.getByTestId("op-status");
    const options = await card.getByLabel("New status").locator("option").allTextContents();
    expect(options).toEqual(["ENABLED", "DISABLED"]);
  });

  test("lists key versions", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-versions");
    await card.getByLabel("Key name").fill("k1");
    await card.getByRole("button", { name: "List versions" }).click();
    await expect(page.getByTestId("versions-result")).toHaveText(
      "v1 DISABLED aes-256-gcm\nv2 ENABLED aes-256-gcm"
    );
    expect(mock.calls.find((c) => c.path === "/keys/k1/versions")?.method).toBe("GET");
  });

  test("hashes data", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-hash");
    await card.getByLabel("Data", { exact: true }).fill("hello");
    await card.getByLabel("Hash algorithm").fill("SHA384");
    await card.getByRole("button", { name: "Hash" }).click();
    await expect(page.getByTestId("hash-result")).toHaveText(`SHA384: ${b64("digest-of-data")}`);
    expect(mock.calls.find((c) => c.path === "/hash")?.body).toEqual({ data: b64("hello"), hash: "SHA384" });
  });

  test("computes an HMAC", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-hmac");
    await card.getByLabel("Key name").fill("mac-key");
    await card.getByLabel("Data", { exact: true }).fill("hello");
    await card.getByRole("button", { name: "Compute HMAC" }).click();
    await expect(page.getByTestId("hmac-result")).toHaveText(b64("mac-of-data"));
    expect(mock.calls.find((c) => c.path === "/hmac/mac-key")?.body).toEqual({ data: b64("hello") });
  });

  test("verifies an HMAC", async ({ page }) => {
    const mock = await openPage(page, { hmacValid: false });
    const card = page.getByTestId("op-verify-hmac");
    await card.getByLabel("Key name").fill("mac-key");
    await card.getByLabel("Data", { exact: true }).fill("hello");
    await card.getByLabel("HMAC (base64)").fill(b64("bad"));
    await card.getByRole("button", { name: "Verify HMAC" }).click();
    await expect(page.getByTestId("verify-hmac-result")).toHaveText("HMAC invalid");
    expect(mock.calls.find((c) => c.path === "/hmac/mac-key/verify")?.body).toEqual({
      data: b64("hello"),
      hmac: b64("bad"),
    });
  });

  test("clears the HMAC verdict when inputs change or verification fails", async ({ page }) => {
    await openPage(page, { hmacValid: true });
    const card = page.getByTestId("op-verify-hmac");
    const result = page.getByTestId("verify-hmac-result");
    const verify = card.getByRole("button", { name: "Verify HMAC" });
    await card.getByLabel("Key name").fill("mac-key");
    await card.getByLabel("Data", { exact: true }).fill("hello");
    await card.getByLabel("HMAC (base64)").fill(b64("good"));
    await verify.click();
    await expect(result).toHaveText("HMAC valid");

    // An edit makes the verdict stale: it no longer describes these inputs.
    await card.getByLabel("HMAC (base64)").fill(b64("other"));
    await expect(result).not.toBeVisible();

    await verify.click();
    await expect(result).toHaveText("HMAC valid");

    // A later verification that fails must not leave the earlier success.
    await page.route("**/api/v1/kms/hmac/mac-key/verify**", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ message: "backend unavailable" }),
      }),
    );
    await verify.click();
    await expect(page.getByTestId("kms-ops-error")).toContainText("backend unavailable");
    await expect(result).not.toBeVisible();
  });

  test("generates random bytes", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-random");
    await card.getByLabel("Number of bytes").fill("4");
    await card.getByRole("button", { name: "Generate random" }).click();
    await expect(page.getByTestId("random-result")).toHaveText(b64("rrrr"));
    expect(mock.calls.find((c) => c.path === "/random")?.body).toEqual({ num_bytes: 4 });
  });

  test("generates a data key", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-data-key");
    await card.getByLabel("Key name").fill("kek");
    await card.getByRole("button", { name: "Generate data key" }).click();
    await expect(page.getByTestId("data-key-result")).toHaveText(
      `plaintext: ${b64("plain-dek")}\nencrypted: ${b64("enc-dek")}`
    );
    expect(mock.calls.find((c) => c.path === "/data-keys")?.body).toEqual({ key_id: "kek" });
  });

  test("generates a wrapped data key", async ({ page }) => {
    const mock = await openPage(page);
    const card = page.getByTestId("op-wrapped-data-key");
    await card.getByLabel("Wrapping key name").fill("kek");
    await card.getByRole("button", { name: "Generate wrapped data key" }).click();
    await expect(page.getByTestId("wrapped-data-key-result")).toHaveText(`wrapped by kek: ${b64("wrapped-dek")}`);
    expect(mock.calls.find((c) => c.path === "/data-keys/wrapped")?.body).toEqual({ wrapping_key_id: "kek" });
  });

  test("shows backend status", async ({ page }) => {
    await openPage(page);
    await page.getByTestId("op-backend").getByRole("button", { name: "Check backend" }).click();
    await expect(page.getByTestId("backend-result")).toHaveText("tpm2: healthy\nsign: yes\nexport: no");
  });

  test("shows the error of a failed operation", async ({ page }) => {
    await openPage(page, { failPath: "/backend/status" });
    await page.getByTestId("op-backend").getByRole("button", { name: "Check backend" }).click();
    await expect(page.getByTestId("kms-ops-error")).toContainText("backend unavailable");
  });
});
