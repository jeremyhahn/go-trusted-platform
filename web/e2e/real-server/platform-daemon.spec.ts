/**
 * Real-server spec for the PlatformDaemon row (#2047, epic #1665 slice 10).
 *
 * Every test reads its expectations from the harness server through the SDK
 * client (`sdk.platform`) and asserts that /platform/services shows what the
 * server returned. No route is mocked.
 */
import { test, expect } from "./fixtures";

const PAGE = "/platform/services";

test.describe("platform daemon: status, version and probes", () => {
  test("status and version cards show what the daemon reports", async ({ adminPage, sdk }) => {
    const status = await sdk.platform.getStatus();
    const version = await sdk.platform.getVersion();
    expect(status.success).toBe(true);
    expect(version.success).toBe(true);

    await adminPage.goto(PAGE);
    await expect(adminPage.getByTestId("daemon-status")).toContainText(
      String(status.data?.status ?? ""),
      { ignoreCase: true }
    );
    await expect(adminPage.getByTestId("daemon-version")).toContainText(
      String(version.data?.version ?? "")
    );
  });

  test("liveness and readiness probes show the server's answer", async ({ adminPage, sdk }) => {
    const live = await sdk.platform.liveness();
    const ready = await sdk.platform.readiness();
    expect(live.success).toBe(true);
    expect(live.data?.alive).toBe(true);
    expect(ready.success).toBe(true);

    await adminPage.goto(PAGE);
    const probes = adminPage.getByTestId("daemon-probes");
    await expect(probes.getByTestId("probe-liveness")).toHaveText(/alive/i);
    await expect(probes.getByTestId("probe-readiness")).toHaveText(
      ready.data?.ready ? /ready/i : /not ready/i
    );
  });
});

test.describe("platform daemon: configuration", () => {
  test("the running configuration is the server's", async ({ adminPage, sdk }) => {
    const config = await sdk.platform.getConfig();
    expect(config.success).toBe(true);

    await adminPage.goto(PAGE);
    const pre = adminPage.getByTestId("daemon-config");
    await expect(pre).not.toHaveText("Loading...");
    for (const key of Object.keys(config.data ?? {}).slice(0, 3)) {
      await expect(pre).toContainText(`"${key}"`);
    }
  });

  test("reload re-reads the configuration and reports success", async ({ adminPage }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Reload Config" }).click();
    await expect(adminPage.getByText("Configuration reloaded")).toBeVisible();
  });

  test("updating an unknown section shows the server's refusal", async ({ adminPage, sdk }) => {
    const refused = await sdk.platform.updateConfig({
      section: "no-such-section-e2e",
      values: { key: "value" },
      persist: false,
    });
    expect(refused.success).toBe(false);

    await adminPage.goto(PAGE);
    await adminPage.getByLabel("Section").fill("no-such-section-e2e");
    await adminPage.getByLabel("Values (JSON)").fill('{"key":"value"}');
    await adminPage.getByRole("button", { name: "Apply Section" }).click();
    await expect(adminPage.getByText("Configuration update failed")).toBeVisible();
  });
});

test.describe("platform daemon: services", () => {
  test("the services table lists every service the server lists", async ({ adminPage, sdk }) => {
    const list = await sdk.platform.listServices();
    expect(list.success).toBe(true);
    const services = list.data?.services ?? [];

    await adminPage.goto(PAGE);
    if (services.length === 0) {
      await expect(adminPage.getByText("No services found")).toBeVisible();
      return;
    }
    for (const svc of services) {
      await expect(adminPage.getByTestId(`service-row-${svc.name}`)).toContainText(svc.status, {
        ignoreCase: true,
      });
    }
  });

  test("details show the server's status for one service", async ({ adminPage, sdk }) => {
    const list = await sdk.platform.listServices();
    const first = list.data?.services?.[0];
    test.skip(!first, "the harness daemon registers no service");
    const detail = await sdk.platform.getServiceStatus(first!.name);
    expect(detail.success).toBe(true);

    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: `Details ${first!.name}` }).click();
    const panel = adminPage.getByTestId("service-detail");
    await expect(panel).toContainText(`Service ${first!.name}`);
    await expect(panel).toContainText(String(detail.data?.status ?? ""), { ignoreCase: true });
  });

  test("restart asks for confirmation and the service is listed again", async ({
    adminPage,
    sdk,
  }) => {
    const list = await sdk.platform.listServices();
    const first = list.data?.services?.[0];
    test.skip(!first, "the harness daemon registers no service");

    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: `Restart ${first!.name}` }).click();
    await expect(adminPage.getByRole("dialog")).toContainText(`Restart ${first!.name}?`);
    await adminPage.getByRole("button", { name: "Confirm" }).click();
    await expect(adminPage.getByText(new RegExp(`Restart ${first!.name}`)).first()).toBeVisible();

    const after = await sdk.platform.getServiceStatus(first!.name);
    expect(after.success).toBe(true);
    await expect(adminPage.getByTestId(`service-row-${first!.name}`)).toBeVisible();
  });

  test("stop then start returns the service to the server's list", async ({ adminPage, sdk }) => {
    const list = await sdk.platform.listServices();
    const first = list.data?.services?.[0];
    test.skip(!first, "the harness daemon registers no service");

    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: `Stop ${first!.name}` }).click();
    await adminPage.getByRole("button", { name: "Confirm" }).click();
    await expect(adminPage.getByText(new RegExp(`Stop ${first!.name}`)).first()).toBeVisible();

    await adminPage.getByRole("button", { name: `Start ${first!.name}` }).click();
    await expect(adminPage.getByText(new RegExp(`Start ${first!.name}`)).first()).toBeVisible();

    const after = await sdk.platform.listServices();
    expect(after.data?.services?.some((s) => s.name === first!.name)).toBe(true);
  });
});

test.describe("platform daemon: entity types and shutdown", () => {
  test("entity types are the server's", async ({ adminPage, sdk }) => {
    const types = await sdk.platform.listEntityTypes();
    await adminPage.goto(PAGE);
    const card = adminPage.getByTestId("entity-types");
    if (!types.success) {
      await expect(card).toContainText(types.error?.message ?? "");
      return;
    }
    const rows = types.data?.entity_types ?? [];
    if (rows.length === 0) {
      await expect(card).toContainText("No entity types");
      return;
    }
    for (const t of rows.slice(0, 5)) {
      await expect(card).toContainText(t.name);
    }
  });

  test("shutdown asks for confirmation; cancel leaves the daemon running", async ({
    adminPage,
    sdk,
  }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByRole("button", { name: "Shut Down Daemon" }).click();
    await expect(adminPage.getByRole("dialog")).toContainText("Shut down the daemon?");
    await adminPage.getByRole("button", { name: "Cancel" }).click();
    await expect(adminPage.getByRole("dialog")).toBeHidden();

    const live = await sdk.platform.liveness();
    expect(live.success).toBe(true);
    expect(live.data?.alive).toBe(true);
  });
});
