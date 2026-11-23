/**
 * Real-server spec for the tenant directory page, /tenant/directory (#2067,
 * UI epic #1665). It runs against the real-server harness: no page.route
 * mocks. Every expectation is checked against what the server answered. The
 * spec never suspends or deletes the fixture tenant: the lifecycle flow works
 * on a throwaway tenant it creates, and a `finally` deletes that tenant if the
 * flow stopped before its own delete.
 */
import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

const LIST_OP = 'GET /api/v1/tenants';
const CREATE_OP = 'POST /api/v1/tenants';
const UPDATE_OP = 'PUT /api/v1/tenants/{id}';
const DELETE_OP = 'DELETE /api/v1/tenants/{id}';
const SUSPEND_OP = 'POST /api/v1/tenants/{id}/suspend';
const RESUME_OP = 'POST /api/v1/tenants/{id}/resume';
const BY_NAME_OP = 'GET /api/v1/tenants/by-name/{name}';
const SYNC_OP = 'POST /api/v1/tenants/sync';

const SUSPENDED = 'TENANT_STATE_SUSPENDED';

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface TenantRecord {
  id?: string;
  name?: string;
  displayName?: string;
  state?: string;
}

async function listCapabilities(sdk: {
  capabilities: { list: () => Promise<{ success: boolean; data?: { capabilities?: Capability[] } }> };
}): Promise<Capability[]> {
  const res = await sdk.capabilities.list();
  expect(res.success).toBeTruthy();
  return res.data?.capabilities ?? [];
}

function capabilityOf(caps: Capability[], op: string): Capability {
  return caps.find((c) => c.op === op) ?? { op, enabled: false };
}

function responseOf(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse((r) => r.request().method() === method && new URL(r.url()).pathname === path);
}

/** Asserts a control is withheld with the server's reason. */
async function expectWithheld(page: Page, name: string, cap: Capability) {
  const button = page.getByRole('button', { name, exact: true }).first();
  await expect(button).toHaveAttribute('data-capability-op', cap.op);
  await expect(button).toHaveAttribute('data-capability-enabled', 'false');
  await expect(button).toBeDisabled();
  if (cap.reason) {
    await expect(button).toHaveAttribute('title', cap.reason);
  }
}

async function readTenant(page: Page, id: string): Promise<TenantRecord> {
  const res = await page.request.get(`/api/v1/tenants/${id}`);
  expect(res.ok()).toBeTruthy();
  const { tenant } = unwrapPayload<{ tenant?: TenantRecord }>(await res.json());
  return tenant ?? {};
}

test.describe('Tenant directory (real server)', () => {
  test.describe.configure({ mode: 'serial' });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tenant/directory');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('the sidebar Tenant group links to the directory page', async ({ adminPage }) => {
    await adminPage.goto('/tenant');
    await adminPage.getByRole('link', { name: 'Directory', exact: true }).click();
    await expect(adminPage).toHaveURL(/\/tenant\/directory$/);
    await expect(adminPage.getByRole('heading', { name: 'Tenant directory' })).toBeVisible();
  });

  test('lists the tenants GET /api/v1/tenants answered the page', async ({ adminPage, sdk }) => {
    const caps = await listCapabilities(sdk);
    const listCap = capabilityOf(caps, LIST_OP);
    const rows = adminPage.locator('[data-testid^="tenant-row-"]');

    if (!listCap.enabled) {
      const reads: string[] = [];
      adminPage.on('request', (r) => {
        if (r.method() === 'GET' && new URL(r.url()).pathname === '/api/v1/tenants') reads.push(r.url());
      });
      await adminPage.goto('/tenant/directory');
      if (listCap.reason) {
        await expect(adminPage.getByText(listCap.reason)).toBeVisible();
      }
      await expect(rows).toHaveCount(0);
      expect(reads).toEqual([]);
      test.skip(true, listCap.reason ?? 'the server does not offer ListTenants');
      return;
    }

    const listRes = responseOf(adminPage, 'GET', '/api/v1/tenants');
    await adminPage.goto('/tenant/directory');
    const res = await listRes;
    if (!res.ok()) {
      // ListTenants is the system tenant's: a refusal is shown, not a list.
      await expect(adminPage.getByRole('alert')).toBeVisible();
      await expect(rows).toHaveCount(0);
      return;
    }
    const { tenants } = unwrapPayload<{ tenants?: TenantRecord[] }>(await res.json());
    const ids = (tenants ?? []).map((t) => t.id ?? '');
    await expect(rows).toHaveCount(ids.length);
    for (const id of ids) {
      await expect(adminPage.getByTestId(`tenant-row-${id}`)).toBeVisible();
    }
  });

  test('finds the fixture tenant by name', async ({ adminPage, sdk, tenant }) => {
    const caps = await listCapabilities(sdk);
    const byName = capabilityOf(caps, BY_NAME_OP);
    await adminPage.goto('/tenant/directory');
    if (!byName.enabled) {
      await expectWithheld(adminPage, 'Find', byName);
      test.skip(true, byName.reason ?? 'the server does not offer GetTenantByName');
      return;
    }

    await adminPage.getByLabel('Find by name').fill(tenant.name);
    const lookupRes = responseOf(adminPage, 'GET', `/api/v1/tenants/by-name/${encodeURIComponent(tenant.name)}`);
    await adminPage.getByRole('button', { name: 'Find', exact: true }).click();
    const res = await lookupRes;
    expect(res.ok()).toBeTruthy();
    const { tenant: found } = unwrapPayload<{ tenant?: TenantRecord }>(await res.json());
    expect(found?.id).toBe(tenant.id);
    const result = adminPage.getByTestId('tenant-lookup-result');
    await expect(result).toContainText(tenant.id);
    await expect(result).toContainText(tenant.name);
  });

  test('gates Create tenant, Find and Sync as the server lists them', async ({ adminPage, sdk }) => {
    const caps = await listCapabilities(sdk);
    await adminPage.goto('/tenant/directory');
    for (const [name, op] of [
      ['Create tenant', CREATE_OP],
      ['Find', BY_NAME_OP],
      ['Sync', SYNC_OP],
    ] as const) {
      const cap = capabilityOf(caps, op);
      const button = adminPage.getByRole('button', { name, exact: true });
      await expect(button).toHaveAttribute('data-capability-op', op);
      await expect(button).toHaveAttribute('data-capability-enabled', cap.enabled ? 'true' : 'false');
      if (!cap.enabled) {
        await expect(button).toBeDisabled();
        if (cap.reason) await expect(button).toHaveAttribute('title', cap.reason);
      }
    }
  });

  test('creates, renames, suspends, resumes and deletes a throwaway tenant', async ({ adminPage, sdk, tenant }) => {
    const caps = await listCapabilities(sdk);
    await adminPage.goto('/tenant/directory');
    const createCap = capabilityOf(caps, CREATE_OP);
    if (!createCap.enabled) {
      await expectWithheld(adminPage, 'Create tenant', createCap);
      test.skip(true, createCap.reason ?? 'the server does not offer CreateTenant');
      return;
    }
    const listCap = capabilityOf(caps, LIST_OP);
    if (!listCap.enabled) {
      test.skip(true, listCap.reason ?? 'the server does not offer ListTenants, so no row controls');
      return;
    }

    const name = `e2e-dir-${Date.now()}`;
    let createdId: string | undefined;
    try {
      await adminPage.getByLabel('Tenant name').fill(name);
      const createRes = responseOf(adminPage, 'POST', '/api/v1/tenants');
      await adminPage.getByRole('button', { name: 'Create tenant', exact: true }).click();
      const created = await createRes;
      if (!created.ok()) {
        // CreateTenant is the system tenant's: the refusal is shown.
        await expect(adminPage.getByRole('alert')).toBeVisible();
        test.skip(true, `the server refused CreateTenant (${created.status()})`);
        return;
      }
      const { tenant: made } = unwrapPayload<{ tenant?: TenantRecord }>(await created.json());
      createdId = made?.id;
      expect(createdId).toBeTruthy();
      expect(createdId).not.toBe(tenant.id);
      const id = createdId as string;
      const row = adminPage.getByTestId(`tenant-row-${id}`);
      await expect(row).toContainText(name);

      const updateCap = capabilityOf(caps, UPDATE_OP);
      if (updateCap.enabled) {
        await row.getByRole('button', { name: 'Edit', exact: true }).click();
        await adminPage.locator(`#tenant-directory-display-${id}`).fill('Initech Directory');
        const putRes = responseOf(adminPage, 'PUT', `/api/v1/tenants/${id}`);
        await row.getByRole('button', { name: 'Save', exact: true }).click();
        expect((await putRes).ok()).toBeTruthy();
        expect((await readTenant(adminPage, id)).displayName).toBe('Initech Directory');
      } else {
        await expect(row.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
      }

      const suspendCap = capabilityOf(caps, SUSPEND_OP);
      const resumeCap = capabilityOf(caps, RESUME_OP);
      if (suspendCap.enabled && resumeCap.enabled) {
        const suspendRes = responseOf(adminPage, 'POST', `/api/v1/tenants/${id}/suspend`);
        await row.getByRole('button', { name: 'Suspend', exact: true }).click();
        expect((await suspendRes).ok()).toBeTruthy();
        expect((await readTenant(adminPage, id)).state).toBe(SUSPENDED);

        const resumeRes = responseOf(adminPage, 'POST', `/api/v1/tenants/${id}/resume`);
        await row.getByRole('button', { name: 'Resume', exact: true }).click();
        expect((await resumeRes).ok()).toBeTruthy();
        expect((await readTenant(adminPage, id)).state).not.toBe(SUSPENDED);
      } else if (!suspendCap.enabled) {
        await expect(row.getByRole('button', { name: 'Suspend', exact: true })).toBeDisabled();
      }

      const deleteCap = capabilityOf(caps, DELETE_OP);
      if (deleteCap.enabled) {
        await row.getByRole('button', { name: 'Delete', exact: true }).click();
        const dialog = adminPage.getByRole('dialog');
        await expect(dialog).toContainText(`Delete tenant ${name}?`);
        const deleteRes = responseOf(adminPage, 'DELETE', `/api/v1/tenants/${id}`);
        await dialog.getByRole('button', { name: 'Delete', exact: true }).click();
        expect((await deleteRes).ok()).toBeTruthy();
        createdId = undefined;
        await expect(row).toHaveCount(0);
      } else {
        await expect(row.getByRole('button', { name: 'Delete', exact: true })).toBeDisabled();
      }
    } finally {
      if (createdId) {
        const left = await adminPage.request.get(`/api/v1/tenants/${createdId}`);
        if (left.ok()) {
          const cleanup = await adminPage.request.delete(`/api/v1/tenants/${createdId}`);
          expect(cleanup.ok()).toBeTruthy();
        }
      }
    }
  });
});
