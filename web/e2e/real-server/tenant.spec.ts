// Real-server spec for the TenantService operations (#2067, UI epic #1665),
// driving the tenant admin pages /admin/tenants/ and /admin/tenants/<id>/.
// State is seeded through the SDK client the harness hands out and every
// assertion compares the page with what the server returns; no route mocks.
import { test, expect } from './fixtures';

const LIST = '/admin/tenants/';
const detail = (id: string) => `/admin/tenants/${encodeURIComponent(id)}/`;

function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** The server may answer TENANT_STATE_ACTIVE or ACTIVE; the pages show ACTIVE. */
function stateName(state: unknown): string {
  return String(state ?? '').replace(/^TENANT_STATE_/, '');
}

test.describe('tenant admin (real server)', () => {
  test('ListTenants: the list shows what the server returns', async ({ adminPage, sdk, tenant }) => {
    const res = await sdk.tenant.listTenants({ limit: 100 });
    expect(res.success).toBe(true);
    const listed = res.data?.tenants ?? [];
    expect(listed.map((t: { name: string }) => t.name)).toContain(tenant.name);

    await adminPage.goto(LIST);
    await expect(adminPage.getByTestId('tenant-list')).toBeVisible();
    await expect(adminPage.getByTestId(`tenant-row-${tenant.id}`)).toContainText(tenant.name);
    await expect(adminPage.getByTestId('tenant-page-info')).toContainText(
      `of ${Number(res.data?.total ?? 0)}`
    );
  });

  test('GetTenantByName: find by name shows the seeded tenant', async ({ adminPage, tenant }) => {
    await adminPage.goto(LIST);
    await adminPage.getByLabel('Tenant name').fill(tenant.name);
    await adminPage.getByRole('button', { name: 'Find' }).click();
    await expect(
      adminPage.getByTestId('search-result').getByTestId(`tenant-row-${tenant.id}`)
    ).toContainText(tenant.name);
  });

  test('CreateTenant and DeleteTenant from the list page', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-tenant');
    await adminPage.goto(LIST);
    await adminPage.locator('#tenant-name').fill(name);
    await adminPage.locator('#tenant-display-name').fill('E2E Tenant');
    await adminPage.getByRole('button', { name: 'Create', exact: true }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText(`Created tenant ${name}`);

    const byName = await sdk.tenant.getTenantByName(name);
    expect(byName.success).toBe(true);
    const created = byName.data!.tenant;
    expect(created.displayName).toBe('E2E Tenant');
    const row = adminPage.getByTestId(`tenant-row-${created.id}`);
    await expect(row).toContainText(name);

    await row.getByRole('button', { name: 'Delete' }).click();
    await adminPage.getByTestId('confirm-action').click();
    await expect(adminPage.getByTestId('action-result')).toHaveText(`Deleted tenant ${name}`);
    await expect
      .poll(async () => {
        const r = await sdk.tenant.getTenant(created.id);
        return !r.success || ['DELETING', 'DELETED'].includes(stateName(r.data?.tenant?.state));
      })
      .toBe(true);
  });

  test('UpdateTenant, SuspendTenant and ResumeTenant from the detail page', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-lifecycle');
    const created = await sdk.tenant.createTenant({ name });
    expect(created.success).toBe(true);
    const id = created.data!.tenant!.id;

    await adminPage.goto(detail(id));
    await adminPage.locator('#detail-display-name').fill('E2E Renamed');
    await adminPage.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant updated');
    expect((await sdk.tenant.getTenant(id)).data?.tenant?.displayName).toBe('E2E Renamed');

    await adminPage.getByRole('button', { name: 'Suspend' }).click();
    await adminPage.getByTestId('confirm-action').click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant suspended');
    expect(stateName((await sdk.tenant.getTenant(id)).data?.tenant?.state)).toBe('SUSPENDED');
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('SUSPENDED');

    await adminPage.getByRole('button', { name: 'Resume' }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Tenant resumed');
    expect(stateName((await sdk.tenant.getTenant(id)).data?.tenant?.state)).toBe('ACTIVE');

    await sdk.tenant.deleteTenant(id);
  });

  test('UpdateQuotas and CheckQuota from the detail page', async ({ adminPage, sdk, tenant }) => {
    await adminPage.goto(detail(tenant.id));
    await adminPage.locator('#quota-max-vms').fill('7');
    await adminPage.getByRole('button', { name: 'Save quotas' }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Quotas updated');
    expect((await sdk.tenant.getQuotas(tenant.id)).data?.compute?.maxVms).toBe(7);
    await expect(adminPage.getByTestId('current-quota')).toContainText('VMs 7');

    const direct = await sdk.tenant.checkQuota({ tenantId: tenant.id, resource: 'vms', amount: 1 });
    expect(direct.success).toBe(true);
    await adminPage.locator('#check-resource').fill('vms');
    await adminPage.locator('#check-amount').fill('1');
    await adminPage.getByRole('button', { name: 'Check quota' }).click();
    await expect(adminPage.getByTestId('action-result')).toContainText(
      direct.data!.available ? 'Quota available for 1 vms' : 'Quota exceeded for 1 vms'
    );
  });

  test('Sync from the detail page', async ({ adminPage, tenant }) => {
    await adminPage.goto(detail(tenant.id));
    await adminPage.getByRole('button', { name: 'Sync tenants' }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Tenants synced');
  });

  test('GetTenantDEKStatus and RotateTenantDEK from the detail page', async ({ adminPage, sdk, tenant }) => {
    const before = await sdk.tenant.getDEKStatus(tenant.id);
    expect(before.success).toBe(true);
    const version = before.data!.dekStatus.version;

    await adminPage.goto(detail(tenant.id));
    await expect(adminPage.getByTestId('dek-status')).toContainText(`Version ${version}`);

    await adminPage.getByRole('button', { name: 'Rotate DEK' }).click();
    await adminPage.getByTestId('confirm-action').click();
    await expect(adminPage.getByTestId('action-result')).toContainText(
      `DEK rotated from version ${version}`
    );
    const after = await sdk.tenant.getDEKStatus(tenant.id);
    expect(after.data!.dekStatus.version).toBeGreaterThan(version);
    await expect(adminPage.getByTestId('dek-status')).toContainText(
      `Version ${after.data!.dekStatus.version}`
    );
  });

  test('InitTenantBarrier, SealTenantBarrier and UnsealTenantBarrier from the detail page', async ({
    adminPage,
    sdk,
  }) => {
    const name = uniqueName('e2e-barrier');
    const created = await sdk.tenant.createTenant({ name });
    expect(created.success).toBe(true);
    const id = created.data!.tenant!.id;

    await adminPage.goto(detail(id));
    await adminPage.getByRole('button', { name: 'Initialise barrier' }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Barrier initialised');

    await adminPage.getByRole('button', { name: 'Seal barrier' }).click();
    await adminPage.getByTestId('confirm-action').click();
    await expect(adminPage.getByTestId('action-result')).toHaveText('Barrier sealed');

    // No unseal key comes back from init, so a wrong key must be refused,
    // and the page must say what the server said.
    const wrongKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
    const direct = await sdk.tenant.unsealBarrier({ tenantId: id, key: wrongKey });
    expect(direct.success).toBe(false);
    await adminPage.getByLabel('Unseal key (base64)').fill(wrongKey);
    await adminPage.getByRole('button', { name: 'Unseal barrier' }).click();
    await expect(adminPage.getByTestId('action-result')).toHaveText(
      direct.error?.message || 'Barrier unseal failed'
    );

    await sdk.tenant.deleteTenant(id);
  });
});
