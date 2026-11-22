import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockPlatformDaemonApi, mockTenantApi } from './fixtures/api-mock';

/**
 * Platform daemon services (#1752): status, version, configuration and
 * reload, the service list, one service's status, and start, stop and
 * restart (stop and restart behind a confirm dialog). Every daemon route
 * is mocked through mockPlatformDaemonApi.
 */

async function openServicesPage(page: Page, config?: Parameters<typeof mockPlatformDaemonApi>[1]) {
  const state = await mockPlatformDaemonApi(page, config);
  await mockTenantApi(page);
  await page.goto('/platform/services');
  await expect(page.getByRole('heading', { name: /platform services/i })).toBeVisible();
  return state;
}

test.describe('Platform daemon services', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('GetStatus: shows the daemon status', async ({ page }) => {
    const state = await openServicesPage(page);
    const card = page.getByTestId('daemon-status');
    await expect(card.getByText('running')).toBeVisible();
    await expect(card.getByText(/abc1234/)).toBeVisible();
    expect(state.calls).toContain('GET /status');
  });

  test('GetVersion: shows the daemon version', async ({ page }) => {
    const state = await openServicesPage(page, { version: { version: '9.8.7' } });
    await expect(page.getByTestId('daemon-version')).toContainText('9.8.7');
    expect(state.calls).toContain('GET /version');
  });

  test('GetConfig: shows the daemon configuration', async ({ page }) => {
    const state = await openServicesPage(page, { config: { log_level: 'debug' } });
    await expect(page.getByTestId('daemon-config')).toContainText('"log_level": "debug"');
    expect(state.calls).toContain('GET /config');
  });

  test('ReloadConfig: reloads the configuration', async ({ page }) => {
    const state = await openServicesPage(page);
    await expect(page.getByTestId('daemon-config')).toContainText('log_level');
    await page.getByRole('button', { name: /reload config/i }).click();
    await expect(page.getByText(/configuration reloaded/i).first()).toBeVisible();
    expect(state.calls).toContain('POST /config/reload');
  });

  test('ListServices: lists the services', async ({ page }) => {
    const state = await openServicesPage(page);
    await expect(page.getByTestId('service-row-kms')).toContainText('running');
    await expect(page.getByTestId('service-row-dns')).toContainText('stopped');
    expect(state.calls).toContain('GET /services');
  });

  test('ListServices: shows an error when the daemon fails', async ({ page }) => {
    await openServicesPage(page, { error: { status: 500, error: 'service manager down' } });
    await expect(page.getByText(/error loading services/i)).toBeVisible();
  });

  test("GetServiceStatus: shows one service's status", async ({ page }) => {
    const state = await openServicesPage(page);
    await page.getByRole('button', { name: 'Details kms' }).click();
    const detail = page.getByTestId('service-detail');
    await expect(detail).toContainText('Service kms');
    await expect(detail).toContainText('Uptime: 2h0m0s');
    expect(state.calls).toContain('GET /services/kms');
  });

  test('StartService: starts a service', async ({ page }) => {
    const state = await openServicesPage(page);
    await page.getByRole('button', { name: 'Start dns' }).click();
    await expect(page.getByTestId('service-row-dns')).toContainText('running');
    expect(state.calls).toContain('POST /services/dns/start');
  });

  test('StopService: stops a service after confirming', async ({ page }) => {
    const state = await openServicesPage(page);
    await page.getByRole('button', { name: 'Stop kms' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Stop kms?');
    expect(state.calls).not.toContain('POST /services/kms/stop');
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    await expect(page.getByTestId('service-row-kms')).toContainText('stopped');
    expect(state.calls).toContain('POST /services/kms/stop');
  });

  test('StopService: cancelling the dialog stops nothing', async ({ page }) => {
    const state = await openServicesPage(page);
    await page.getByRole('button', { name: 'Stop kms' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toBeHidden();
    await expect(page.getByTestId('service-row-kms')).toContainText('running');
    expect(state.calls).not.toContain('POST /services/kms/stop');
  });

  test('RestartService: restarts a service after confirming', async ({ page }) => {
    const state = await openServicesPage(page);
    await page.getByRole('button', { name: 'Restart kms' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Restart kms?');
    await dialog.getByRole('button', { name: 'Confirm' }).click();
    await expect(page.getByText(/kms restarted/i).first()).toBeVisible();
    expect(state.calls).toContain('POST /services/kms/restart');
  });
});
