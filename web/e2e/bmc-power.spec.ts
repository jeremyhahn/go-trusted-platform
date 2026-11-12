import { test, expect, Page } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
import { mockBmcApi, mockTenantApi } from "./fixtures/api-mock";
import type { BmcApiMockConfig } from "./fixtures/api-mock";

/**
 * BMC profile page (#1736): every BMC operation with a REST route is
 * reachable from the page, with the API mocked at the route layer through
 * `mockBmcApi`. The mutating operations run only after a confirm dialog.
 */

async function openProfile(page: Page, config: BmcApiMockConfig = {}) {
  const mock = await mockBmcApi(page, config);
  await mockTenantApi(page);
  await page.goto("/devices/bmc/__placeholder__/");
  // pushState is only router-integrated once the app has hydrated.
  await page.getByText("Select a BMC profile").waitFor();
  await page.waitForLoadState("networkidle");
  await page.evaluate(() => window.history.pushState(null, "", "/devices/bmc/r640-01/"));
  await expect(page.getByRole("heading", { name: "BMC r640-01" })).toBeVisible();
  return mock;
}

async function confirmDialog(page: Page, title: string) {
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: title })).toBeVisible();
  await dialog.getByRole("button", { name: "Confirm" }).click();
  await expect(dialog).toBeHidden();
}

test.describe("BMC power, boot device, virtual media, sensors and provision (#1736)", () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test("shows the power status", async ({ page }) => {
    await openProfile(page);
    await expect(page.getByTestId("bmc-power-state")).toHaveText("On");
  });

  test("shows the boot device", async ({ page }) => {
    await openProfile(page);
    await expect(page.getByTestId("bmc-boot-device")).toHaveText("disk");
  });

  test("sets the boot device after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByLabel("New boot device").selectOption("pxe");
    await page.getByRole("button", { name: "Set boot device" }).click();
    expect(requests).toEqual([]);
    await confirmDialog(page, "Set boot device");
    expect(requests).toEqual([{ method: "POST", op: "boot-device", body: { device: "pxe", persistent: false } }]);
    await expect(page.getByTestId("bmc-boot-device")).toHaveText("pxe");
  });

  test("cancelling the confirm dialog sends nothing", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByRole("button", { name: "Provision" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("dialog")).toBeHidden();
    expect(requests).toEqual([]);
  });

  test("shows the virtual media status", async ({ page }) => {
    await openProfile(page, { state: { virtualMedia: { inserted: true, image: "rescue.iso" } } });
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("Mounted: rescue.iso");
  });

  test("mounts an ISO after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("No media mounted");
    await page.getByLabel("ISO image").fill("installer.iso");
    await page.getByRole("button", { name: "Mount ISO", exact: true }).click();
    await confirmDialog(page, "Mount ISO");
    expect(requests).toEqual([{ method: "POST", op: "virtual-media", body: { image: "installer.iso" } }]);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("Mounted: installer.iso");
  });

  test("unmounts the ISO after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page, { state: { virtualMedia: { inserted: true, image: "rescue.iso" } } });
    await page.getByRole("button", { name: "Unmount ISO" }).click();
    await confirmDialog(page, "Unmount ISO");
    expect(requests).toEqual([{ method: "DELETE", op: "virtual-media", body: null }]);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("No media mounted");
  });

  test("shows the sensors", async ({ page }) => {
    await openProfile(page);
    const sensors = page.getByTestId("bmc-sensors");
    await expect(sensors).toContainText("CPU1 Temp");
    await expect(sensors).toContainText("54 C");
    await expect(sensors).toContainText("7200 RPM");
  });

  test("shows the system info", async ({ page }) => {
    await openProfile(page);
    const info = page.getByTestId("bmc-system-info");
    await expect(info).toContainText("PowerEdge R640");
    await expect(info).toContainText("SN-R640-01");
  });

  test("provisions after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByRole("button", { name: "Provision" }).click();
    await confirmDialog(page, "Provision BMC");
    expect(requests).toEqual([{ method: "POST", op: "provision", body: {} }]);
    await expect(page.getByTestId("bmc-provision-state")).toHaveText("provisioning");
  });

  test("shows the provision status", async ({ page }) => {
    await openProfile(page, { state: { provision: { state: "provisioned", message: "done" } } });
    await expect(page.getByTestId("bmc-provision-state")).toHaveText("provisioned");
  });

  test("shows the web certificate", async ({ page }) => {
    await openProfile(page);
    const cert = page.getByTestId("bmc-certificate");
    await expect(cert).toContainText("CN=idrac-r640-01");
    await expect(cert).toContainText("MIIBbmcweb");
  });

  test("a failing part shows its error and leaves the rest", async ({ page }) => {
    await openProfile(page, { errors: { sensors: { status: 503, error: "bmc: sensors unavailable" } } });
    await expect(page.getByTestId("bmc-sensors-error")).toHaveText("bmc: sensors unavailable");
    await expect(page.getByTestId("bmc-power-state")).toHaveText("On");
  });
});
