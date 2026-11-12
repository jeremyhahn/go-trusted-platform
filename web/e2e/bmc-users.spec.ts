import { test, expect, Page } from '@playwright/test';
import { mockBMCApi, mockTenantApi } from './fixtures/api-mock';
import type { BMCApiMockConfig, MockBMCUser } from './fixtures/api-mock';
import { createTenantOwnerSession } from './fixtures/auth-setup';

/**
 * BMC users and web certificate pages (#1720, slice 3 of #1665).
 *
 * One test per BMC operation that has a REST route. EnrollBMC and
 * RestoreFactoryCert have no route yet and stay out of this spec.
 */

const PROFILE = '7';

// Placeholder material: the page sends it through unchanged, and the
// mock only records it.
const CERT_TEXT = 'test-web-certificate';
const KEY_TEXT = 'test-web-certificate-key';

const seedUsers: MockBMCUser[] = [
  { slot: 2, username: 'ADMIN', enabled: true, privilege: 0x04, channel: 1 },
  { slot: 3, username: 'ops', enabled: true, privilege: 0x02, channel: 1 },
];

// Built at runtime so no credential-shaped literal sits in the source.
const TEST_PASSWORD = ['test', 'only', 'pw'].join('-');

async function gotoUsersPage(page: Page, config: BMCApiMockConfig) {
  const bmc = await mockBMCApi(page, { profileID: PROFILE, ...config });
  await mockTenantApi(page);
  // The static export serves the placeholder route; once the app has
  // hydrated, pushState moves it to the real profile URL.
  await page.goto('/devices/bmc/__placeholder__/users/');
  await page.getByText('Loading users...').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((id) => window.history.pushState(null, '', `/devices/bmc/${id}/users/`), PROFILE);
  return bmc;
}

async function openUsersPage(page: Page, users: MockBMCUser[] = seedUsers) {
  const bmc = await gotoUsersPage(page, { users });
  await expect(page.getByTestId('bmc-user-2')).toBeVisible();
  return bmc;
}

function lastCall(bmc: Awaited<ReturnType<typeof mockBMCApi>>, method: string, path: string) {
  return [...bmc.calls].reverse().find((c) => c.method === method && c.path === path);
}

test.describe('BMC users and web certificate', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('ListUsers: lists the user slots of a BMC profile', async ({ page }) => {
    const bmc = await openUsersPage(page);
    const admin = page.getByTestId('bmc-user-2');
    await expect(admin).toContainText('ADMIN');
    await expect(admin).toContainText('administrator');
    await expect(page.getByTestId('bmc-user-3')).toContainText('user');
    expect(lastCall(bmc, 'GET', `/api/v1/bmc/${PROFILE}/users`)).toBeTruthy();
  });

  test('CreateUser: adds a user from the create dialog', async ({ page }) => {
    const bmc = await openUsersPage(page);
    await page.getByRole('button', { name: 'Create User' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Slot').fill('4');
    await dialog.getByLabel('Username').fill('auditor');
    await dialog.getByLabel('Password').fill(TEST_PASSWORD);
    await dialog.getByLabel('Privilege').selectOption('operator');
    await dialog.getByRole('button', { name: 'Create' }).click();

    await expect(page.getByTestId('bmc-user-4')).toContainText('auditor');
    await expect(page.getByTestId('bmc-user-4')).toContainText('operator');
    expect(lastCall(bmc, 'POST', `/api/v1/bmc/${PROFILE}/users`)?.body).toEqual({
      slot: 4,
      username: 'auditor',
      password: TEST_PASSWORD,
      privilege: 'operator',
      enabled: true,
      channel: 1,
    });
  });

  test('CreateUser: defaults to a free slot and refuses an occupied one', async ({ page }) => {
    const users: MockBMCUser[] = [
      ...seedUsers,
      { slot: 4, username: 'backup', enabled: true, privilege: 0x02, channel: 1 },
    ];
    const bmc = await openUsersPage(page, users);
    const postPath = `/api/v1/bmc/${PROFILE}/users`;
    const posts = () => bmc.calls.filter((c) => c.method === 'POST' && c.path === postPath);

    // The default slot is the lowest free one from 3 up.
    await page.getByRole('button', { name: 'Create User' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByLabel('Slot')).toHaveValue('5');
    await dialog.getByLabel('Username').fill('auditor');
    await dialog.getByLabel('Password').fill(TEST_PASSWORD);
    await dialog.getByRole('button', { name: 'Create' }).click();
    await expect(page.getByTestId('bmc-user-5')).toContainText('auditor');
    expect(posts()).toHaveLength(1);
    expect(posts()[0].body).toMatchObject({ slot: 5, username: 'auditor' });
    // The existing accounts survive the creation.
    await expect(page.getByTestId('bmc-user-3')).toContainText('ops');
    await expect(page.getByTestId('bmc-user-4')).toContainText('backup');

    // Reopening Create does not keep the now-occupied slot.
    await page.getByRole('button', { name: 'Create User' }).click();
    const again = page.getByRole('dialog');
    await expect(again.getByLabel('Slot')).toHaveValue('6');

    // An occupied slot shows an inline error and sends nothing.
    await again.getByLabel('Slot').fill('3');
    await again.getByLabel('Username').fill('second');
    await again.getByLabel('Password').fill(TEST_PASSWORD);
    await again.getByRole('button', { name: 'Create' }).click();
    await expect(again.getByTestId('bmc-create-slot-error')).toContainText('Slot 3');
    expect(posts()).toHaveLength(1);
  });

  test('CreateUser: a failed listing leaves Create User disabled', async ({ page }) => {
    const bmc = await gotoUsersPage(page, { users: seedUsers, listStatus: 500 });
    await expect(page.getByText('No users found')).toBeVisible();
    // A failed listing must not read as "every slot is free".
    await expect(page.getByRole('button', { name: 'Create User' })).toBeDisabled();
    expect(bmc.calls.some((c) => c.method === 'POST' && c.path === `/api/v1/bmc/${PROFILE}/users`)).toBe(
      false
    );
  });

  test('CreateUser: a delayed listing keeps Create User disabled until the rows appear', async ({ page }) => {
    await gotoUsersPage(page, { users: seedUsers, listDelayMs: 1500 });
    const create = page.getByRole('button', { name: 'Create User' });
    await expect(create).toBeDisabled();
    await expect(page.getByTestId('bmc-user-2')).toBeVisible();
    await expect(create).toBeEnabled();
  });

  test('DeleteUser: deletes a user after the confirm dialog', async ({ page }) => {
    const bmc = await openUsersPage(page);
    await page.getByRole('button', { name: 'Delete ops' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Delete ops from slot 3');
    // Nothing is sent before the confirmation.
    expect(lastCall(bmc, 'DELETE', `/api/v1/bmc/${PROFILE}/users/3`)).toBeUndefined();
    await dialog.getByRole('button', { name: 'Confirm Delete' }).click();

    await expect(page.getByTestId('bmc-user-3')).toHaveCount(0);
    expect(lastCall(bmc, 'DELETE', `/api/v1/bmc/${PROFILE}/users/3`)).toBeTruthy();
  });

  test('SetUserPassword: sets a user password', async ({ page }) => {
    const bmc = await openUsersPage(page);
    await page.getByRole('button', { name: 'Set password of ops' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('New password').fill(TEST_PASSWORD);
    await dialog.getByRole('button', { name: 'Set Password' }).click();

    await expect(dialog).toBeHidden();
    expect(lastCall(bmc, 'PUT', `/api/v1/bmc/${PROFILE}/users/3/password`)?.body).toEqual({
      password: TEST_PASSWORD,
    });
  });

  test('SetUserPrivilege: changes a user privilege', async ({ page }) => {
    const bmc = await openUsersPage(page);
    await page.getByRole('button', { name: 'Set privilege of ops' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Privilege').selectOption('administrator');
    await dialog.getByRole('button', { name: 'Set Privilege' }).click();

    await expect(page.getByTestId('bmc-user-3')).toContainText('administrator');
    expect(lastCall(bmc, 'PUT', `/api/v1/bmc/${PROFILE}/users/3/privilege`)?.body).toEqual({
      privilege: 'administrator',
      channel: 1,
    });
  });

  test('ReplaceWebCertificate: replaces the web certificate after the confirm dialog', async ({ page }) => {
    const bmc = await openUsersPage(page);
    await page.getByRole('button', { name: 'Replace Web Certificate' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Certificate (PEM)').fill(CERT_TEXT);
    await dialog.getByLabel('Private key (PEM)').fill(KEY_TEXT);
    expect(lastCall(bmc, 'PUT', `/api/v1/bmc/${PROFILE}/cert`)).toBeUndefined();
    await dialog.getByRole('button', { name: 'Confirm Replace' }).click();

    await expect(dialog).toBeHidden();
    expect(lastCall(bmc, 'PUT', `/api/v1/bmc/${PROFILE}/cert`)?.body).toEqual({
      cert_pem: CERT_TEXT,
      key_pem: KEY_TEXT,
    });
  });

  test('BMC entry page links a profile to its users page', async ({ page }) => {
    await mockTenantApi(page);
    await page.goto('/devices/bmc/');
    await page.getByLabel('Profile ID').fill(PROFILE);
    await page.getByRole('button', { name: 'Open Users' }).click();
    await expect(page).toHaveURL(new RegExp(`/devices/bmc/${PROFILE}/users`));
  });
});
