import { test, expect, Page } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
import { mockBmcApi, mockTenantApi } from "./fixtures/api-mock";
import type { BmcApiMockConfig } from "./fixtures/api-mock";

/** The numeric device-profile ID every test uses. */
const PROFILE_ID = "1";

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

  test("boot device offers exactly the server's devices", async ({ page }) => {
    await openProfile(page);
    const options = page.getByLabel("New boot device").locator("option");
    await expect(options).toHaveText(["none", "pxe", "disk", "cdrom", "virtual_media"]);
  });

  test("sets the virtual_media boot device", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByLabel("New boot device").selectOption("virtual_media");
    await page.getByRole("button", { name: "Set boot device" }).click();
    await confirmDialog(page, "Set boot device");
    expect(requests).toEqual([
      { method: "POST", op: "boot-device", body: { device: "virtual_media", persistent: false } },
    ]);
    await expect(page.getByTestId("bmc-boot-device")).toHaveText("virtual_media");
  });

  test("cancelling the confirm dialog sends nothing", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByRole("button", { name: "Provision" }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("dialog")).toBeHidden();
    expect(requests).toEqual([]);
  });

  test("shows the virtual media status", async ({ page }) => {
    await openProfile(page, { state: { virtualMedia: { mounted: true, image_url: "rescue.iso" } } });
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("rescue.iso");
    await expect(page.getByRole("button", { name: "Unmount ISO" })).toBeEnabled();
  });

  test("mounts an ISO after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("No media");
    await expect(page.getByRole("button", { name: "Unmount ISO" })).toBeDisabled();
    await page.getByLabel("ISO URL").fill("installer.iso");
    await page.getByRole("button", { name: "Mount ISO", exact: true }).click();
    await confirmDialog(page, "Mount ISO");
    expect(requests).toEqual([{ method: "POST", op: "virtual-media", body: { iso_url: "installer.iso" } }]);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("installer.iso");
  });

  test("unmounts the ISO after confirmation", async ({ page }) => {
    const { requests } = await openProfile(page, { state: { virtualMedia: { mounted: true, image_url: "rescue.iso" } } });
    await page.getByRole("button", { name: "Unmount ISO" }).click();
    await confirmDialog(page, "Unmount ISO");
    expect(requests).toEqual([{ method: "DELETE", op: "virtual-media", body: null }]);
    await expect(page.getByTestId("bmc-virtual-media")).toHaveText("No media");
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

  test("provisions the host after a confirmation that names the shutdown and OS install", async ({ page }) => {
    const { requests } = await openProfile(page);
    await page.getByRole("button", { name: "Provision" }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("powers the host off");
    await expect(dialog).toContainText("installs an operating system");
    await confirmDialog(page, "Provision host");
    expect(requests).toEqual([{ method: "POST", op: "provision", body: {} }]);
    await expect(page.getByTestId("bmc-provision-state")).toHaveText("pending");
  });

  test("shows the provision status", async ({ page }) => {
    await openProfile(page, {
      state: {
        provision: {
          provision_id: "prov-2",
          profile_id: "r640-01",
          status: "installing",
          message: "waiting for the OS install",
          started_at: "2026-11-12T00:00:00Z",
          updated_at: "2026-11-12T00:10:00Z",
        },
      },
    });
    await expect(page.getByTestId("bmc-provision-state")).toHaveText("installing");
  });

  test("shows the web certificate", async ({ page }) => {
    await openProfile(page);
    const cert = page.getByTestId("bmc-certificate");
    await expect(cert).toContainText("CN=idrac-r640-01");
    await expect(cert).toContainText("SHA256:5B:9D:3F:2E");
  });

  test("a failing part shows its error and leaves the rest", async ({ page }) => {
    await openProfile(page, { errors: { sensors: { status: 503, error: "bmc: sensors unavailable" } } });
    await expect(page.getByTestId("bmc-sensors-error")).toHaveText("bmc: sensors unavailable");
    await expect(page.getByTestId("bmc-power-state")).toHaveText("On");
  });
});

test.describe("BMC profile ID is the numeric device-profile ID (#1736)", () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test("the landing page opens the profile page for a numeric ID", async ({ page }) => {
    await mockBmcApi(page);
    await mockTenantApi(page);
    await page.goto("/devices/bmc/");
    await page.getByLabel("BMC profile ID").fill(PROFILE_ID);
    await page.getByRole("button", { name: "Open" }).click();
    await expect(page).toHaveURL(new RegExp(`/devices/bmc/${PROFILE_ID}/$`));
  });

  test("the landing page refuses a non-numeric ID", async ({ page }) => {
    await mockBmcApi(page);
    await mockTenantApi(page);
    await page.goto("/devices/bmc/");
    await page.getByLabel("BMC profile ID").fill("abc");
    await page.getByRole("button", { name: "Open" }).click();
    await expect(page.getByTestId("bmc-profile-id-error")).toContainText("number");
    await expect(page).toHaveURL(/\/devices\/bmc\/$/);
  });

  test("the mock answers 404 for a non-numeric profile ID, as the server routes do", async ({ page }) => {
    const { requests } = await mockBmcApi(page);
    await mockTenantApi(page);
    await page.goto("/devices/bmc/");
    const statuses = await page.evaluate(
      async (id) =>
        Promise.all(
          [`/api/v1/bmc/abc/power`, `/api/v1/bmc/${id}/power`].map(async (u) => (await fetch(u)).status)
        ),
      PROFILE_ID
    );
    expect(statuses).toEqual([404, 200]);
    expect(requests).toEqual([]);
  });
});
