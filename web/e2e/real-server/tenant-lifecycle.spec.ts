import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';

/**
 * Tenant lifecycle, quotas, sync and tenant DEK rotation (#1758, slice 30 of
 * #1665) against the real server.
 *
 * Ported from web/e2e/tenant-lifecycle.spec.ts (#2037). The mocked spec
 * answered /api/v1/tenants through mockTenantLifecycleApi with a canned
 * tenant "acme". Here each test creates its own tenant through the `sdk`
 * fixture, looks it up on /tenant/lifecycle, reads the result back from the
 * server, and deletes the tenant afterwards.
 *
 * Gaps (docs/plans/1665-port-3.md): a failing sync ("completed with
 * errors"), a quota check forced to fail, and the canned DEK version.
 */

type SDK = PlatformClient;

interface Seeded {
  id: string;
  name: string;
  displayName: string;
}

function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

async function seedTenant(sdk: SDK): Promise<Seeded> {
  const name = uniqueName('e2e-tl');
  const displayName = `E2E ${name}`;
  const res = await sdk.tenant.createTenant({
    name,
    displayName,
    computeQuota: { maxVms: 10, maxContainers: 5, maxVcpus: 8, maxMemoryMb: 4096 },
  });
  if (!res.success || !res.data?.tenant) {
    throw new Error(`tenant.createTenant failed: ${JSON.stringify(res.error)}`);
  }
  return { id: res.data.tenant.id, name, displayName };
}

async function tenantState(sdk: SDK, id: string): Promise<string> {
  const res = await sdk.tenant.getTenant(id);
  return res.success ? String(res.data?.tenant?.state ?? '') : '';
}

async function openLifecycle(page: Page): Promise<void> {
  await page.goto('/tenant/lifecycle');
  await expect(page.locator('h1').filter({ hasText: /Tenant Lifecycle/i })).toBeVisible();
}

async function lookUp(page: Page, name: string): Promise<void> {
  await page.getByLabel('Tenant name').fill(name);
  await page.getByRole('button', { name: 'Look up' }).click();
  await expect(page.getByTestId('tenant-details')).toBeVisible();
}

async function confirmDialog(page: Page, title: string, button: string): Promise<void> {
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(title)).toBeVisible();
  await dialog.getByRole('button', { name: button }).click();
  await expect(dialog).toBeHidden();
}

test.describe('Tenant lifecycle (real server)', () => {
  let seeded: Seeded | undefined;

  test.beforeEach(async ({ sdk }) => {
    seeded = await seedTenant(sdk);
  });

  test.afterEach(async ({ sdk }) => {
    if (seeded) await sdk.tenant.deleteTenant(seeded.id);
    seeded = undefined;
  });

  test('GetTenantByName looks a tenant up by name', async ({ adminPage }) => {
    const s = seeded!;
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await expect(adminPage.getByTestId('tenant-details')).toContainText(s.displayName);
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('ACTIVE');
  });

  test('GetTenantByName shows an error for an unknown name', async ({ adminPage, sdk }) => {
    const unknown = uniqueName('e2e-nobody');
    expect((await sdk.tenant.getTenantByName(unknown)).success).toBe(false);

    await openLifecycle(adminPage);
    await adminPage.getByLabel('Tenant name').fill(unknown);
    await adminPage.getByRole('button', { name: 'Look up' }).click();
    await expect(adminPage.getByRole('alert')).toBeVisible();
    await expect(adminPage.getByTestId('tenant-details')).toHaveCount(0);
  });

  test('UpdateTenant saves the display name', async ({ adminPage, sdk }) => {
    const s = seeded!;
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByLabel('Display name').fill('Acme Renamed');
    await adminPage.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(adminPage.getByRole('status')).toHaveText('Tenant updated');
    await expect(adminPage.getByTestId('tenant-details')).toContainText('Acme Renamed');
    await expect
      .poll(async () => (await sdk.tenant.getTenant(s.id)).data?.tenant?.displayName)
      .toBe('Acme Renamed');
  });

  test('DeleteTenant asks for confirmation first', async ({ adminPage, sdk }) => {
    const s = seeded!;
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByRole('button', { name: 'Delete' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    expect((await sdk.tenant.getTenant(s.id)).success).toBe(true);

    await adminPage.getByRole('button', { name: 'Delete' }).click();
    await confirmDialog(adminPage, 'Delete tenant', 'Delete');
    await expect(adminPage.getByRole('status')).toHaveText(`Tenant ${s.name} deleted`);
    await expect(adminPage.getByTestId('tenant-details')).toHaveCount(0);
    await expect.poll(async () => (await sdk.tenant.getTenant(s.id)).success).toBe(false);
    seeded = undefined;
  });

  test('SuspendTenant asks for confirmation first', async ({ adminPage, sdk }) => {
    const s = seeded!;
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByRole('button', { name: 'Suspend' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText('changes its state only');
    expect(await tenantState(sdk, s.id)).toContain('ACTIVE');
    await confirmDialog(adminPage, 'Suspend tenant', 'Suspend');
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('SUSPENDED');
    await expect.poll(() => tenantState(sdk, s.id)).toContain('SUSPENDED');
  });

  test('ResumeTenant resumes a suspended tenant', async ({ adminPage, sdk }) => {
    const s = seeded!;
    expect((await sdk.tenant.suspendTenant(s.id)).success).toBe(true);
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('SUSPENDED');
    await adminPage.getByRole('button', { name: 'Resume' }).click();
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('ACTIVE');
    await expect.poll(() => tenantState(sdk, s.id)).toContain('ACTIVE');
  });

  test('UpdateQuotas saves new quota limits', async ({ adminPage, sdk }) => {
    const s = seeded!;
    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByLabel('Maximum VMs').fill('12');
    await adminPage.getByRole('button', { name: 'Save quotas' }).click();
    await expect(adminPage.getByRole('status')).toHaveText('Quotas updated');
    await expect
      .poll(async () => {
        const res = await sdk.tenant.getQuotas(s.id);
        return ((res.data ?? {}) as { compute?: Record<string, unknown> }).compute;
      })
      .toMatchObject({ maxVms: 12, maxContainers: 5, maxVcpus: 8, maxMemoryMb: 4096 });
  });

  test('CheckQuota reports whether a request fits', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const res = await sdk.tenant.checkQuota({ tenantId: s.id, resource: 'vcpus', amount: 64 });
    expect(res.success).toBe(true);
    const available = res.data?.available === true;

    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByLabel('Resource').fill('vcpus');
    await adminPage.getByLabel('Amount').fill('64');
    const post = adminPage.waitForResponse(
      (r) => r.url().includes(`/${s.id}/quota-check`) && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Check quota' }).click();
    expect((await post).request().postDataJSON()).toEqual({ resource: 'vcpus', amount: 64 });
    const result = adminPage.getByTestId('quota-check-result');
    if (available) {
      await expect(result).not.toHaveText(/^Not available/);
      await expect(result).not.toBeEmpty();
    } else {
      await expect(result).toHaveText(/^Not available/);
    }
  });

  test('Sync triggers a tenant sync', async ({ adminPage }) => {
    await openLifecycle(adminPage);
    const post = adminPage.waitForResponse(
      (r) => r.url().includes('/tenants/sync') && r.request().method() === 'POST',
    );
    await adminPage.getByRole('button', { name: 'Sync tenants' }).click();
    expect((await post).ok()).toBe(true);
    await expect(adminPage.getByRole('status')).toHaveText('Tenant sync started');
  });

  test('GetTenantDEKStatus shows the DEK version', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const dek = (await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus;
    expect(typeof dek?.version).toBe('number');

    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByRole('button', { name: 'Load DEK status' }).click();
    if (dek?.algorithm) {
      await expect(adminPage.getByTestId('dek-status')).toContainText(dek.algorithm);
    }
    await expect(adminPage.getByTestId('dek-version')).toHaveText(String(dek?.version));
    await expect(adminPage.getByTestId('dek-usage-note')).toBeVisible();
    await expect(adminPage.getByTestId('dek-status')).not.toContainText('%');
  });

  test('RotateTenantDEK asks for confirmation first', async ({ adminPage, sdk }) => {
    const s = seeded!;
    const before = (await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus?.version;
    expect(typeof before).toBe('number');
    const next = (before as number) + 1;

    await openLifecycle(adminPage);
    await lookUp(adminPage, s.name);
    await adminPage.getByRole('button', { name: 'Rotate DEK' }).click();
    expect((await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus?.version).toBe(before);
    await confirmDialog(adminPage, 'Rotate tenant DEK', 'Rotate');
    await expect(adminPage.getByRole('status')).toHaveText(`DEK rotated to version ${next}`);
    await expect(adminPage.getByTestId('dek-version')).toHaveText(String(next));
    await expect
      .poll(async () => (await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus?.version)
      .toBe(next);
  });
});
