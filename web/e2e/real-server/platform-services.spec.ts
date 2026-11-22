import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import { daemonApi, type DaemonApi } from './fixtures/daemon-api';

/**
 * Platform daemon services (#1752) against the real server.
 *
 * Ported from web/e2e/platform-services.spec.ts (#2037). The mocked spec
 * answered every daemon route through mockPlatformDaemonApi; here each value
 * the page shows is read back from the harness daemon through the `sdk`
 * fixture. Service actions run on one service the daemon lists, and every
 * test that changes a service's state starts it again afterwards.
 *
 * Gaps (docs/plans/1665-port-3.md): the injected 500 on ListServices.
 */

/** Services safe to stop in the harness, in order of preference. */
const PREFERRED = ['ntp', 'dns', 'pxe', 'vpn'];

async function openServicesPage(page: Page): Promise<void> {
  await page.goto('/platform/services');
  await expect(page.getByRole('heading', { name: /platform services/i })).toBeVisible();
}

async function listedServices(api: DaemonApi): Promise<{ name: string; status: string }[]> {
  const res = await api.listServices();
  if (!res.success || !res.data) {
    throw new Error(`platform.listServices failed: ${JSON.stringify(res.error)}`);
  }
  return (res.data.services ?? []).map((s) => ({ name: s.name, status: String(s.status ?? '') }));
}

async function pickService(api: DaemonApi): Promise<string> {
  const services = await listedServices(api);
  expect(services.length).toBeGreaterThan(0);
  const preferred = PREFERRED.find((n) => services.some((s) => s.name === n));
  return preferred ?? services[0].name;
}

async function serviceStatus(api: DaemonApi, name: string): Promise<string> {
  const res = await api.getServiceStatus(name);
  if (!res.success || !res.data) {
    throw new Error(`platform.getServiceStatus(${name}) failed: ${JSON.stringify(res.error)}`);
  }
  return String(res.data.status ?? '');
}

/** The version string from a GET /version reply, flat or wrapped. */
function versionString(data: unknown): string {
  if (typeof data === 'string') return data;
  if (!data || typeof data !== 'object') return '';
  const v = (data as Record<string, unknown>).version;
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object') {
    const inner = (v as Record<string, unknown>).version;
    if (typeof inner === 'string') return inner;
  }
  return '';
}

test.describe('Platform daemon services (real server)', () => {
  test('GetStatus: shows the daemon status', async ({ adminPage }) => {
    const res = await daemonApi(adminPage).getStatus();
    expect(res.success).toBe(true);
    const status = (res.data ?? {}) as Record<string, unknown>;

    await openServicesPage(adminPage);
    const card = adminPage.getByTestId('daemon-status');
    if (typeof status.status === 'string' && status.status) {
      await expect(card).toContainText(status.status);
    }
    if (typeof status.git_commit === 'string' && status.git_commit) {
      await expect(card).toContainText(status.git_commit);
    }
  });

  test('GetVersion: shows the daemon version', async ({ adminPage, sdk }) => {
    const res = await sdk.platform.getVersion();
    expect(res.success).toBe(true);
    const version = versionString(res.data);
    expect(version).not.toBe('');

    await openServicesPage(adminPage);
    await expect(adminPage.getByTestId('daemon-version')).toContainText(version);
  });

  test('GetConfig: shows the daemon configuration', async ({ adminPage, sdk }) => {
    const res = await sdk.platform.getConfig();
    expect(res.success).toBe(true);
    const keys = Object.keys((res.data ?? {}) as Record<string, unknown>);
    expect(keys.length).toBeGreaterThan(0);

    await openServicesPage(adminPage);
    await expect(adminPage.getByTestId('daemon-config')).toContainText(`"${keys[0]}"`);
  });

  test('ReloadConfig: reloads the configuration', async ({ adminPage }) => {
    await openServicesPage(adminPage);
    await expect(adminPage.getByTestId('daemon-config')).not.toBeEmpty();
    const reload = adminPage.waitForResponse(
      (r) => r.url().includes('/config/reload') && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: /reload config/i }).click();
    expect((await reload).ok()).toBe(true);
    await expect(adminPage.getByText(/configuration reloaded/i).first()).toBeVisible();
  });

  test('ListServices: lists the services the daemon reports', async ({ adminPage }) => {
    const api = daemonApi(adminPage);
    const services = await listedServices(api);
    expect(services.length).toBeGreaterThan(0);

    await openServicesPage(adminPage);
    for (const svc of services) {
      const row = adminPage.getByTestId(`service-row-${svc.name}`);
      await expect(row).toBeVisible();
      if (svc.status) await expect(row).toContainText(svc.status);
    }
  });

  test("GetServiceStatus: shows one service's status", async ({ adminPage }) => {
    const api = daemonApi(adminPage);
    const name = await pickService(api);
    const res = await api.getServiceStatus(name);
    expect(res.success).toBe(true);

    await openServicesPage(adminPage);
    await adminPage.getByRole('button', { name: `Details ${name}` }).click();
    const detail = adminPage.getByTestId('service-detail');
    await expect(detail).toContainText(`Service ${name}`);
    if (res.data?.uptime) await expect(detail).toContainText('Uptime:');
  });

  test.describe('service actions', () => {
    test.describe.configure({ mode: 'serial' });

    test('StartService: starts a stopped service', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const name = await pickService(api);
      try {
        const stopped = await api.stopService(name);
        expect(stopped.success).toBe(true);
        await expect.poll(() => serviceStatus(api, name)).not.toBe('running');

        await openServicesPage(adminPage);
        await adminPage.getByRole('button', { name: `Start ${name}` }).click();
        await expect(adminPage.getByTestId(`service-row-${name}`)).toContainText('running');
        await expect.poll(() => serviceStatus(api, name)).toBe('running');
      } finally {
        await api.startService(name);
      }
    });

    test('StopService: stops a service after confirming', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const name = await pickService(api);
      try {
        await api.startService(name);
        await expect.poll(() => serviceStatus(api, name)).toBe('running');

        await openServicesPage(adminPage);
        await adminPage.getByRole('button', { name: `Stop ${name}` }).click();
        const dialog = adminPage.getByRole('dialog');
        await expect(dialog).toContainText(`Stop ${name}?`);
        expect(await serviceStatus(api, name)).toBe('running');
        await dialog.getByRole('button', { name: 'Confirm' }).click();
        await expect(adminPage.getByTestId(`service-row-${name}`)).toContainText('stopped');
        await expect.poll(() => serviceStatus(api, name)).not.toBe('running');
      } finally {
        await api.startService(name);
      }
    });

    test('StopService: cancelling the dialog stops nothing', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const name = await pickService(api);
      await api.startService(name);
      await expect.poll(() => serviceStatus(api, name)).toBe('running');

      await openServicesPage(adminPage);
      await adminPage.getByRole('button', { name: `Stop ${name}` }).click();
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
      await expect(adminPage.getByRole('dialog')).toBeHidden();
      await expect(adminPage.getByTestId(`service-row-${name}`)).toContainText('running');
      expect(await serviceStatus(api, name)).toBe('running');
    });

    test('RestartService: restarts a service after confirming', async ({ adminPage }) => {
      const api = daemonApi(adminPage);
      const name = await pickService(api);
      try {
        await api.startService(name);

        await openServicesPage(adminPage);
        await adminPage.getByRole('button', { name: `Restart ${name}` }).click();
        const dialog = adminPage.getByRole('dialog');
        await expect(dialog).toContainText(`Restart ${name}?`);
        const restart = adminPage.waitForResponse(
          (r) => r.url().includes(`/services/${name}/restart`) && r.request().method() === 'POST',
        );
        await dialog.getByRole('button', { name: 'Confirm' }).click();
        expect((await restart).ok()).toBe(true);
        await expect(adminPage.getByText(new RegExp(`${name} restarted`, 'i')).first()).toBeVisible();
        await expect.poll(() => serviceStatus(api, name)).toBe('running');
      } finally {
        await api.startService(name);
      }
    });
  });
});
