import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';

/**
 * Admin tenant lifecycle, quota and DEK pages (#1673) against the real
 * server.
 *
 * Ported from web/e2e/tenant-admin.spec.ts (#2037). The mocked spec answered
 * every route through mockAdminTenantsApi with a canned tenant-1 "acme". Here
 * each test creates its own tenant through the `sdk` fixture, drives
 * /admin/tenants or /admin/tenants/<id>, reads the result back from the
 * server, and deletes the tenant afterwards. The fixture's own tenant is
 * never suspended, sealed or deleted.
 *
 * Gaps (docs/plans/1665-port-3.md): paging past 100 tenants, the canned
 * DEK version and usage, a quota check forced to fail, and unsealing with a
 * key the harness holds.
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
  const name = uniqueName('e2e-ta');
  const displayName = `E2E ${name}`;
  const res = await sdk.tenant.createTenant({
    name,
    displayName,
    computeQuota: { maxVms: 10, maxContainers: 5, maxVcpus: 40, maxMemoryMb: 65536 },
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

async function confirm(page: Page): Promise<void> {
  const dialog = page.getByTestId('confirm-dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByTestId('confirm-action').click();
}

function detail(s: Seeded): string {
  return `/admin/tenants/${encodeURIComponent(s.id)}/`;
}

test.describe('Admin tenant lifecycle, quota and DEK (real server)', () => {
  let seeded: Seeded | undefined;

  test.beforeEach(async ({ sdk }) => {
    seeded = await seedTenant(sdk);
  });

  test.afterEach(async ({ sdk }) => {
    if (seeded) await sdk.tenant.deleteTenant(seeded.id);
    seeded = undefined;
  });

  test.describe('tenant list', () => {
    test('ListTenants shows every tenant', async ({ adminPage, sdk, tenant }) => {
      const s = seeded!;
      const suspended = await sdk.tenant.suspendTenant(s.id);
      expect(suspended.success).toBe(true);

      await adminPage.goto('/admin/tenants/');
      const list = adminPage.getByTestId('tenant-list');
      await expect(list.getByRole('link', { name: s.name })).toBeVisible();
      await expect(list.getByRole('link', { name: tenant.name })).toBeVisible();
      await expect(adminPage.getByTestId(`tenant-row-${s.id}`)).toContainText('SUSPENDED');
    });

    test('CreateTenant adds a tenant', async ({ adminPage, sdk }) => {
      const name = uniqueName('e2e-new');
      let createdId: string | undefined;
      try {
        await adminPage.goto('/admin/tenants/');
        await adminPage.getByLabel('Name', { exact: true }).fill(name);
        await adminPage.getByLabel('Display name').fill('Initech');
        await adminPage.getByRole('button', { name: 'Create' }).click();
        await expect(adminPage.getByTestId('action-result')).toHaveText(`Created tenant ${name}`);
        await expect(
          adminPage.getByTestId('tenant-list').getByRole('link', { name }),
        ).toBeVisible();

        const res = await sdk.tenant.getTenantByName(name);
        expect(res.success).toBe(true);
        const t = (res.data as { tenant?: { id: string; displayName?: string } } | undefined)?.tenant;
        createdId = t?.id;
        expect(t?.displayName).toBe('Initech');
      } finally {
        if (createdId) await sdk.tenant.deleteTenant(createdId);
      }
    });

    test('GetTenantByName finds a tenant by name', async ({ adminPage }) => {
      const s = seeded!;
      await adminPage.goto('/admin/tenants/');
      await adminPage.getByLabel('Tenant name').fill(s.name);
      await adminPage.getByRole('button', { name: 'Find' }).click();
      await expect(
        adminPage.getByTestId('search-result').getByRole('link', { name: s.name }),
      ).toBeVisible();

      await adminPage.getByLabel('Tenant name').fill(uniqueName('e2e-nobody'));
      await adminPage.getByRole('button', { name: 'Find' }).click();
      await expect(adminPage.getByTestId('search-result')).toHaveCount(0);
      await expect(adminPage.getByTestId('action-result')).not.toHaveText('');
    });

    test('DeleteTenant removes a tenant after confirm', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await adminPage.goto('/admin/tenants/');
      const row = adminPage.getByTestId(`tenant-row-${s.id}`);
      await row.getByRole('button', { name: 'Delete' }).click();
      // Cancel first: nothing is deleted.
      await adminPage.getByTestId('confirm-dialog').getByRole('button', { name: 'Cancel' }).click();
      expect((await sdk.tenant.getTenant(s.id)).success).toBe(true);

      await row.getByRole('button', { name: 'Delete' }).click();
      await confirm(adminPage);
      await expect(adminPage.getByTestId('action-result')).toHaveText(`Deleted tenant ${s.name}`);
      await expect(row).toHaveCount(0);
      await expect.poll(async () => (await sdk.tenant.getTenant(s.id)).success).toBe(false);
      seeded = undefined;
    });
  });

  test.describe('tenant detail', () => {
    test('UpdateTenant saves the display name', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      const field = adminPage.getByLabel('Display name');
      await expect(field).toHaveValue(s.displayName);
      await field.fill('Acme Industries');
      await adminPage.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant updated');
      await expect
        .poll(async () => (await sdk.tenant.getTenant(s.id)).data?.tenant?.displayName)
        .toBe('Acme Industries');
    });

    test('UpdateTenant refuses an empty display name', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      const field = adminPage.getByLabel('Display name');
      await expect(field).toHaveValue(s.displayName);
      await field.fill('');
      await adminPage.getByRole('button', { name: 'Save', exact: true }).click();
      await expect(adminPage.getByTestId('action-result')).toHaveText('Display name cannot be empty');
      expect((await sdk.tenant.getTenant(s.id)).data?.tenant?.displayName).toBe(s.displayName);
    });

    test('SuspendTenant suspends after confirm', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      await adminPage.getByRole('button', { name: 'Suspend' }).click();
      await confirm(adminPage);
      await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant suspended');
      await expect(adminPage.getByTestId('tenant-state')).toHaveText('SUSPENDED');
      await expect(adminPage.getByRole('button', { name: 'Resume' })).toBeVisible();
      await expect.poll(() => tenantState(sdk, s.id)).toContain('SUSPENDED');
    });

    test('ResumeTenant resumes a suspended tenant', async ({ adminPage, sdk }) => {
      const s = seeded!;
      expect((await sdk.tenant.suspendTenant(s.id)).success).toBe(true);
      await adminPage.goto(detail(s));
      await adminPage.getByRole('button', { name: 'Resume' }).click();
      await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant resumed');
      await expect(adminPage.getByTestId('tenant-state')).toHaveText('ACTIVE');
      await expect.poll(() => tenantState(sdk, s.id)).toContain('ACTIVE');
    });

    test('UpdateQuotas saves quotas', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      await expect(adminPage.getByTestId('current-quota')).toContainText('VMs 10');
      // Only Max VMs is edited: the other limits, maxContainers included,
      // must be kept, because the server replaces the whole compute section.
      await adminPage.getByLabel('Max VMs').fill('20');
      await adminPage.getByRole('button', { name: 'Save quotas' }).click();
      await expect(adminPage.getByTestId('action-result')).toHaveText('Quotas updated');
      await expect(adminPage.getByTestId('current-quota')).toContainText(
        'VMs 20, vCPUs 40, memory 65536 MB',
      );
      await expect
        .poll(async () => {
          const res = await sdk.tenant.getQuotas(s.id);
          const data = (res.data ?? {}) as { compute?: Record<string, unknown> };
          return data.compute;
        })
        .toMatchObject({ maxVms: 20, maxContainers: 5, maxVcpus: 40, maxMemoryMb: 65536 });
    });

    test('CheckQuota reports a resource check', async ({ adminPage, sdk }) => {
      const s = seeded!;
      const res = await sdk.tenant.checkQuota({ tenantId: s.id, resource: 'vcpus', amount: 8 });
      expect(res.success).toBe(true);
      const available = res.data?.available === true;

      await adminPage.goto(detail(s));
      await adminPage.getByLabel('Resource').fill('vcpus');
      await adminPage.getByLabel('Amount').fill('8');
      const post = adminPage.waitForResponse(
        (r) => r.url().includes(`/${s.id}/quota-check`) && r.request().method() === 'POST',
      );
      await adminPage.getByRole('button', { name: 'Check quota' }).click();
      const reply = await post;
      expect(reply.request().postDataJSON()).toEqual({ resource: 'vcpus', amount: 8 });
      const result = adminPage.getByTestId('action-result');
      if (available) {
        await expect(result).not.toHaveText('Quota exceeded for 8 vcpus');
        await expect(result).not.toHaveText('');
      } else {
        await expect(result).toHaveText('Quota exceeded for 8 vcpus');
      }
    });

    test('Sync syncs the tenants', async ({ adminPage }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      const post = adminPage.waitForResponse(
        (r) => r.url().includes('/tenants/sync') && r.request().method() === 'POST',
      );
      await adminPage.getByRole('button', { name: 'Sync tenants' }).click();
      expect((await post).ok()).toBe(true);
      await expect(adminPage.getByTestId('action-result')).toHaveText('Tenants synced');
    });

    test('GetTenantDEKStatus shows the DEK status', async ({ adminPage, sdk }) => {
      const s = seeded!;
      const res = await sdk.tenant.getDEKStatus(s.id);
      expect(res.success).toBe(true);
      const dek = res.data?.dekStatus;

      await adminPage.goto(detail(s));
      const status = adminPage.getByTestId('dek-status');
      await expect(status).toContainText(`Version ${dek?.version ?? ''}`);
      if (dek?.algorithm) await expect(status).toContainText(dek.algorithm);
    });

    test('RotateTenantDEK rotates after confirm', async ({ adminPage, sdk }) => {
      const s = seeded!;
      const before = (await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus?.version;
      expect(typeof before).toBe('number');
      const next = (before as number) + 1;

      await adminPage.goto(detail(s));
      await adminPage.getByRole('button', { name: 'Rotate DEK' }).click();
      await confirm(adminPage);
      await expect(adminPage.getByTestId('action-result')).toHaveText(
        `DEK rotated from version ${before} to ${next}`,
      );
      await expect(adminPage.getByTestId('dek-status')).toContainText(`Version ${next}`);
      await expect
        .poll(async () => (await sdk.tenant.getDEKStatus(s.id)).data?.dekStatus?.version)
        .toBe(next);
    });

    test('InitTenantBarrier initialises the barrier', async ({ adminPage }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      // Tenant barriers take no Shamir settings: the server refuses any
      // non-zero threshold or shares.
      await expect(adminPage.getByLabel('Threshold')).toHaveCount(0);
      await expect(adminPage.getByLabel('Shares')).toHaveCount(0);
      const post = adminPage.waitForResponse(
        (r) => r.url().includes(`/${s.id}/barrier/init`) && r.request().method() === 'POST',
      );
      await adminPage.getByRole('button', { name: 'Initialise barrier' }).click();
      const reply = await post;
      expect(reply.request().postDataJSON()).toEqual({});
      expect(reply.ok()).toBe(true);
      await expect(adminPage.getByTestId('action-result')).toHaveText('Barrier initialised');
    });

    test('UnsealTenantBarrier sends the key and shows the server answer', async ({ adminPage }) => {
      const s = seeded!;
      await adminPage.goto(detail(s));
      await adminPage.getByLabel('Unseal key (base64)').fill('dW5zZWFsLWtleQ==');
      const post = adminPage.waitForResponse(
        (r) => r.url().includes(`/${s.id}/barrier/unseal`) && r.request().method() === 'POST',
      );
      await adminPage.getByRole('button', { name: 'Unseal barrier' }).click();
      const reply = await post;
      expect(reply.request().postDataJSON()).toEqual({ key: 'dW5zZWFsLWtleQ==' });
      const result = adminPage.getByTestId('action-result');
      if (reply.ok()) {
        await expect(result).toHaveText('Barrier unsealed');
      } else {
        await expect(result).not.toHaveText('Barrier unsealed');
      }
    });

    test('SealTenantBarrier seals after confirm', async ({ adminPage, sdk }) => {
      const s = seeded!;
      await sdk.tenant.initBarrier({ tenantId: s.id });
      await adminPage.goto(detail(s));
      await adminPage.getByRole('button', { name: 'Seal barrier' }).click();
      const post = adminPage.waitForResponse(
        (r) => r.url().includes(`/${s.id}/barrier/seal`) && r.request().method() === 'POST',
      );
      await confirm(adminPage);
      expect((await post).ok()).toBe(true);
      await expect(adminPage.getByTestId('action-result')).toHaveText('Barrier sealed');
    });
  });
});
