import type { Locator, Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';

/**
 * EAB credentials against the real platformd (#2050, epic #1665).
 *
 * No page.route mock: each credential is seeded through the SDK and the
 * page drives the server's EABService. The EAB routes mount only when the
 * daemon runs an EAB service, so every test first asks the capabilities
 * endpoint and skips, with the reason, when it offers none.
 *
 * MarkCredentialUsed is not driven: the ACME server marks a credential when
 * an account binds it; the console has no control for it.
 */

const CREATE_OP = 'POST /api/v1/eab/credentials';

/** Skips the test unless the daemon offers the EAB create route. */
async function requireEAB(sdk: PlatformClient): Promise<void> {
  const res = await sdk.capabilities.list();
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const enabled = (res.data?.capabilities ?? []).some((c) => c.op === CREATE_OP && c.enabled);
  test.skip(!enabled, `the daemon offers no EAB service (${CREATE_OP} is not enabled)`);
}

interface Seeded {
  id: number;
  keyId: string;
  hmacKey: string;
}

/** Seeds an active credential in the admin's tenant through the SDK. */
async function seedCredential(sdk: PlatformClient, tenantId: string): Promise<Seeded> {
  const res = await sdk.eab.create({ profileId: 1, tenantId, expiresInSeconds: 3600 });
  expect(res.success, JSON.stringify(res.error)).toBeTruthy();
  const c = res.data?.credential;
  if (!c || !c.keyId || !c.hmacKey) throw new Error(`[real-server] eab.create returned no credential: ${JSON.stringify(res.data)}`);
  return { id: Number(c.id), keyId: c.keyId, hmacKey: c.hmacKey };
}

/** Asserts that a gated control is enabled by the capability gate. */
async function expectGateOpen(control: Locator): Promise<void> {
  await expect(control).toHaveAttribute('data-capability-enabled', 'true');
}

function credentialRow(page: Page, keyId: string): Locator {
  return page.getByRole('row').filter({ hasText: keyId });
}

test.describe('EAB credentials', () => {
  test.beforeEach(async ({ sdk }) => {
    await requireEAB(sdk);
  });

  test('lists a seeded credential, shows its detail, revokes and deletes it', async ({ adminPage, sdk, tenant }) => {
    const seeded = await seedCredential(sdk, tenant.id);
    adminPage.on('dialog', (d) => void d.accept());

    await adminPage.goto('/ca/eab');
    const row = credentialRow(adminPage, seeded.keyId);
    await expect(row).toBeVisible();

    const details = adminPage.getByRole('button', { name: `Details ${seeded.keyId}` });
    await expectGateOpen(details);
    await details.click();
    const detail = adminPage.getByTestId('eab-credential-detail');
    await expect(detail).toBeVisible();
    await expect(detail.getByRole('img', { name: `QR code for ${seeded.keyId}` })).toBeVisible();
    await expect(detail.getByText('Enrolment URL:')).toBeVisible();

    const revoke = row.getByRole('button', { name: 'Revoke' });
    await expectGateOpen(revoke);
    await revoke.click();
    await expect(row).toContainText(/revoked/i);

    const del = row.getByRole('button', { name: 'Delete' });
    await expectGateOpen(del);
    await del.click();
    await expect(credentialRow(adminPage, seeded.keyId)).toHaveCount(0);
  });

  test('creates a credential and shows its HMAC key once', async ({ adminPage, tenant }) => {
    await adminPage.goto('/ca/eab/new');
    await adminPage.getByLabel('Profile ID').fill('1');
    await adminPage.getByLabel('Tenant ID').fill(tenant.id);
    await adminPage.getByLabel('Expires in (seconds)').fill('3600');
    const submit = adminPage.getByRole('button', { name: 'Create credential' });
    await expectGateOpen(submit);
    await submit.click();
    await expect(adminPage.getByText('Copy the HMAC key now; it will not be shown again.')).toBeVisible();
    await expect(adminPage.getByText('HMAC key', { exact: true })).toBeVisible();
  });

  test('finds a credential by key ID and validates it', async ({ adminPage, sdk, tenant }) => {
    const seeded = await seedCredential(sdk, tenant.id);

    await adminPage.goto('/ca/eab');
    await adminPage.getByLabel('Key ID').fill(seeded.keyId);
    const result = adminPage.getByTestId('eab-tool-result');

    const find = adminPage.getByRole('button', { name: 'Find by key ID' });
    await expectGateOpen(find);
    await find.click();
    await expect(result).toContainText(`Found ${seeded.keyId}`);

    await adminPage.getByLabel('HMAC key').fill(seeded.hmacKey);
    const validate = adminPage.getByRole('button', { name: 'Validate' });
    await expectGateOpen(validate);
    await validate.click();
    await expect(result).toHaveText('Valid');
  });
});
