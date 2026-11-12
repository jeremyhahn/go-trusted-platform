import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import {
  createMockDeviceTemplate,
  mockDeviceTemplateApi,
  mockTenantApi,
  RecordedRequest,
} from './fixtures/api-mock';

/**
 * Device templates, profile assignment and config lookup (#1737, slice 12
 * of epic #1665). Every operation is reached from /devices/templates and
 * answered by the mock in fixtures/api-mock.ts.
 */

async function openTemplates(page: Page, findConfigNull = false) {
  const mock = await mockDeviceTemplateApi(page, {
    templates: [createMockDeviceTemplate()],
    ...(findConfigNull ? { findConfigResult: null } : {}),
  });
  await mockTenantApi(page);
  await page.goto('/devices/templates');
  await expect(page.getByRole('cell', { name: 'edge-node', exact: true })).toBeVisible();
  return mock;
}

async function openRowMenu(page: Page) {
  const row = page.getByRole('row').filter({ hasText: 'edge-node' });
  await row.getByRole('button', { name: 'Open menu' }).click();
}

function lastRequest(requests: RecordedRequest[], method: string, path: string) {
  return [...requests].reverse().find((r) => r.method === method && r.path === path);
}

test.describe('Device templates', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('CreateTemplate creates a template from the dialog', async ({ page }) => {
    const mock = await openTemplates(page);
    await page.getByRole('button', { name: 'Create Template' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Template Name').fill('gateway-baseline');
    await dialog.getByLabel('Description').fill('Gateway defaults');
    await dialog.getByRole('button', { name: 'Create Template' }).click();

    await expect.poll(() => lastRequest(mock.requests, 'POST', '/api/v1/device/templates')).toBeTruthy();
    const req = lastRequest(mock.requests, 'POST', '/api/v1/device/templates');
    expect(req?.body).toMatchObject({ name: 'gateway-baseline', description: 'Gateway defaults' });
    await expect(page.getByText('Template created').first()).toBeVisible();
  });

  test('GetTemplate shows a template\'s details', async ({ page }) => {
    const mock = await openTemplates(page);
    await openRowMenu(page);
    await page.getByRole('menuitem', { name: 'View Details' }).click();

    const details = page.getByTestId('template-details');
    await expect(details).toBeVisible();
    await expect(details).toContainText('edge-node');
    await expect(details).toContainText('Edge node baseline');
    expect(lastRequest(mock.requests, 'GET', '/api/v1/device/templates/42')).toBeTruthy();
  });

  test('UpdateTemplate saves an edited template', async ({ page }) => {
    const mock = await openTemplates(page);
    await openRowMenu(page);
    await page.getByRole('menuitem', { name: 'Edit Template' }).click();

    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Template Name').fill('edge-node-v2');
    await dialog.getByRole('button', { name: 'Save Changes' }).click();

    await expect.poll(() => lastRequest(mock.requests, 'PUT', '/api/v1/device/templates/42')).toBeTruthy();
    expect(lastRequest(mock.requests, 'PUT', '/api/v1/device/templates/42')?.body).toMatchObject({
      name: 'edge-node-v2',
    });
    await expect(page.getByText('Template updated').first()).toBeVisible();
  });

  test('DeleteTemplate removes a template after confirmation', async ({ page }) => {
    const mock = await openTemplates(page);

    // Cancelling the confirm dialog sends nothing.
    await openRowMenu(page);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await expect(page.getByRole('dialog')).toContainText('Delete template?');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    expect(lastRequest(mock.requests, 'DELETE', '/api/v1/device/templates/42')).toBeUndefined();

    await openRowMenu(page);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();

    await expect.poll(() => lastRequest(mock.requests, 'DELETE', '/api/v1/device/templates/42')).toBeTruthy();
    await expect(page.getByText('Template deleted').first()).toBeVisible();
  });

  test('CreateProfileFromTemplate creates a profile from a template', async ({ page }) => {
    const mock = await openTemplates(page);
    await openRowMenu(page);
    await page.getByRole('menuitem', { name: 'Create Profile' }).click();

    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('EK Serial Number').fill('EK123');
    await dialog.getByRole('button', { name: 'Create Profile' }).click();

    const path = '/api/v1/device/templates/42/create-profile';
    await expect.poll(() => lastRequest(mock.requests, 'POST', path)).toBeTruthy();
    expect(lastRequest(mock.requests, 'POST', path)?.body).toHaveProperty('overrides');
    await expect(page.getByText('Profile created').first()).toBeVisible();
  });

  test('FindConfigForDevice looks up the config for a device', async ({ page }) => {
    const mock = await openTemplates(page);
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill('EK123');
    await panel.getByRole('button', { name: 'Find Config' }).click();

    await expect(page.getByTestId('find-config-result')).toContainText('edge-node-profile');
    const req = lastRequest(mock.requests, 'GET', '/api/v1/device/profiles/find-config');
    expect(req?.query).toContain('ek_serial=EK123');
    // The found profile fills the profile ID for assignment.
    await expect(panel.getByLabel('Profile ID')).toHaveValue('7');
  });

  test('FindConfigForDevice reports a device no profile matches', async ({ page }) => {
    await openTemplates(page, true);
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('MAC Address').fill('aa:bb:cc:dd:ee:ff');
    await panel.getByRole('button', { name: 'Find Config' }).click();
    await expect(page.getByTestId('find-config-result')).toContainText('No profile matches');
  });

  test('AssignProfileToDevice assigns a profile to a device', async ({ page }) => {
    const mock = await openTemplates(page);
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill('EK123');
    await panel.getByLabel('Profile ID').fill('7');
    await panel.getByRole('button', { name: 'Assign Profile' }).click();

    const path = '/api/v1/device/profiles/7/assign';
    await expect.poll(() => lastRequest(mock.requests, 'POST', path)).toBeTruthy();
    expect(lastRequest(mock.requests, 'POST', path)?.body).toMatchObject({ ekSerial: 'EK123' });
    await expect(page.getByText('Profile assigned').first()).toBeVisible();
  });

  test('UnassignProfileFromDevice unassigns a profile after confirmation', async ({ page }) => {
    const mock = await openTemplates(page);
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('Profile ID').fill('7');
    await panel.getByRole('button', { name: 'Unassign Profile' }).click();

    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Unassign profile?');
    await dialog.getByRole('button', { name: 'Unassign' }).click();

    const path = '/api/v1/device/profiles/7/unassign';
    await expect.poll(() => lastRequest(mock.requests, 'POST', path)).toBeTruthy();
    await expect(page.getByText('Profile unassigned').first()).toBeVisible();
  });
});
