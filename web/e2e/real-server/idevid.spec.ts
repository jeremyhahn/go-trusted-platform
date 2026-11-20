/**
 * Real-server spec for the IDevID and IAK page (issue #2055, epic #1665).
 *
 * Every assertion is on what the harness server returns: state is read and
 * seeded through the `sdk` fixture, never through route mocks.
 */
import { test, expect } from "./fixtures";

const PAGE = "/tpm/idevid";

test.describe("IDevID and IAK page", () => {
  test("status badges and device attributes match the server", async ({ adminPage, sdk }) => {
    const idevid = await sdk.idevid.hasIDevID();
    const iak = await sdk.idevid.hasIAK();
    const attrs = await sdk.idevid.getDeviceAttributes();
    expect(idevid.success).toBe(true);
    expect(iak.success).toBe(true);
    expect(attrs.success).toBe(true);

    await adminPage.goto(PAGE);
    await expect(adminPage.getByRole("heading", { name: "IDevID and IAK" })).toBeVisible();
    await expect(adminPage.getByTestId("idevid-status")).toHaveText(
      idevid.data?.exists ? "Present" : "Absent"
    );
    await expect(adminPage.getByTestId("iak-status")).toHaveText(iak.data?.exists ? "Present" : "Absent");

    const manufacturer = (attrs.data?.attributes as Record<string, string | undefined> | undefined)
      ?.tpmManufacturer;
    if (manufacturer) {
      await expect(adminPage.getByTestId("device-attributes")).toContainText(manufacturer);
    }
  });

  test("Generate IAK leaves the IAK present on the server", async ({ adminPage, sdk }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Generate IAK" }).click();
    await expect(adminPage.getByTestId("iak-status")).toHaveText("Present");

    const iak = await sdk.idevid.hasIAK();
    expect(iak.success).toBe(true);
    expect(iak.data?.exists).toBe(true);
  });

  test("Create IAK CSR shows the CSR the server issued", async ({ adminPage, sdk }) => {
    const seeded = await sdk.idevid.generateIAK();
    expect(seeded.success).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Create IAK CSR" }).click();
    const result = adminPage.getByTestId("idevid-result");
    await expect(result).toContainText("IAK CSR created");
    await expect(result.locator("pre")).not.toBeEmpty();
  });

  test("Create LDevID shows the issued certificate", async ({ adminPage, sdk }) => {
    expect((await sdk.idevid.generateIAK()).success).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByLabel("LDevID common name").fill("e2e-ldevid");
    await adminPage.getByRole("button", { name: "Create LDevID" }).click();
    const result = adminPage.getByTestId("idevid-result");
    await expect(result).toContainText("LDevID created");
    await expect(result.locator("pre")).toContainText("BEGIN CERTIFICATE");
  });

  test("Delete IAK is refused by the server and the IAK stays", async ({ adminPage, sdk }) => {
    expect((await sdk.idevid.generateIAK()).success).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Delete IAK", exact: true }).click();
    await adminPage.getByRole("button", { name: /confirm|delete/i }).last().click();
    await expect(adminPage.getByText("Error deleting IAK")).toBeVisible();

    const iak = await sdk.idevid.hasIAK();
    expect(iak.data?.exists).toBe(true);
  });

  test("Install and delete the IAK certificate round-trip through the server", async ({ adminPage, sdk }) => {
    expect((await sdk.idevid.generateIAK()).success).toBe(true);
    const ldevid = await sdk.idevid.createLDevID({ template: { commonName: "e2e-iak-cert" } });
    expect(ldevid.success).toBe(true);
    const raw = ldevid.data?.certificatePem ?? "";
    const pem = raw.startsWith("-----BEGIN") ? raw : atob(raw);

    await adminPage.goto(PAGE);
    await adminPage.getByLabel("IAK certificate (PEM)").fill(pem);
    await adminPage.getByRole("button", { name: "Install IAK certificate" }).click();
    await expect(adminPage.getByText("IAK certificate installed")).toBeVisible();
    expect((await sdk.idevid.getIAKCertificate()).success).toBe(true);

    await adminPage.getByRole("button", { name: "Delete IAK certificate" }).click();
    await adminPage.getByRole("button", { name: /confirm|delete/i }).last().click();
    await expect(adminPage.getByText("IAK certificate deleted")).toBeVisible();
    expect((await sdk.idevid.getIAKCertificate()).success).toBe(false);
  });

  test("Install IDevID certificate is answered by the server", async ({ adminPage, sdk }) => {
    expect((await sdk.idevid.generateIAK()).success).toBe(true);
    const ldevid = await sdk.idevid.createLDevID({ template: { commonName: "e2e-idevid-cert" } });
    expect(ldevid.success).toBe(true);
    const raw = ldevid.data?.certificatePem ?? "";
    const pem = raw.startsWith("-----BEGIN") ? raw : atob(raw);

    await adminPage.goto(PAGE);
    await adminPage.getByLabel("IDevID certificate (PEM)").fill(pem);
    await adminPage.getByRole("button", { name: "Install IDevID certificate" }).click();
    await expect(
      adminPage.getByText(/IDevID certificate installed|Error installing IDevID certificate/)
    ).toBeVisible();
  });

  test("Flush transient contexts reports the server's count", async ({ adminPage }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Flush transient contexts" }).click();
    await adminPage.getByRole("button", { name: /confirm|flush/i }).last().click();
    const result = adminPage.getByTestId("idevid-result");
    await expect(result).toContainText("Transient contexts flushed");
    await expect(result).toContainText(/Flushed \d+ contexts/);
  });

  test("Activate credential with a malformed blob shows the server's error", async ({ adminPage }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByLabel("Credential blob (base64)").fill("bm90LWEtY3JlZGVudGlhbA==");
    await adminPage.getByLabel("Encrypted secret (base64)").fill("bm90LWEtc2VjcmV0");
    await adminPage.getByRole("button", { name: "Activate credential" }).click();
    await expect(adminPage.getByText("Error activating credential")).toBeVisible();
  });
});
