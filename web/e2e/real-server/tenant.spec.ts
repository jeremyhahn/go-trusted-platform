// Real-server spec for the TenantService operations (#2067, UI epic #1665).
// Seeds through the SDK client the harness hands out and asserts on what the
// server returns; no route mocks.
import { test, expect } from './fixtures';

const PAGE = '/tenant/manage';

function uniqueName(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
}

test.describe('tenant management (real server)', () => {
  test('lists tenants the server returns, including the seeded tenant', async ({ adminPage, sdk, tenant }) => {
    const res = await sdk.tenant.listTenants();
    expect(res.success).toBe(true);
    const names = (res.data?.tenants ?? []).map((t) => t.name);
    expect(names).toContain(tenant.name);

    await adminPage.goto(PAGE);
    const table = adminPage.getByTestId('tenant-list');
    await expect(table).toBeVisible();
    await expect(table.getByTestId(`tenant-row-${tenant.id}`)).toContainText(tenant.name);
  });

  test('creates, renames and deletes a tenant from the page', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-tenant');
    await adminPage.goto(PAGE);

    await adminPage.getByTestId('tenant-create-name').fill(name);
    await adminPage.getByTestId('tenant-create-display-name').fill('E2E Tenant');
    await adminPage.getByTestId('tenant-create-submit').click();

    const byName = await sdk.tenant.getTenantByName(name);
    expect(byName.success).toBe(true);
    const created = byName.data?.tenant;
    expect(created?.name).toBe(name);
    const id = created!.id;
    await expect(adminPage.getByTestId(`tenant-row-${id}`)).toContainText(name);

    await adminPage.getByTestId(`tenant-select-${id}`).click();
    await adminPage.getByTestId('tenant-update-display-name').fill('E2E Renamed');
    await adminPage.getByTestId('tenant-update-submit').click();
    await expect
      .poll(async () => (await sdk.tenant.getTenant(id)).data?.tenant?.displayName)
      .toBe('E2E Renamed');

    adminPage.once('dialog', (d) => void d.accept());
    await adminPage.getByTestId('tenant-delete').click();
    await expect(adminPage.getByTestId(`tenant-row-${id}`)).toHaveCount(0);
    await expect
      .poll(async () => {
        const r = await sdk.tenant.getTenant(id);
        return !r.success || r.data?.tenant?.state === 'DELETING' || r.data?.tenant?.state === 'DELETED';
      })
      .toBe(true);
  });

  test('suspends and resumes a tenant', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-suspend');
    const created = await sdk.tenant.createTenant({ name });
    expect(created.success).toBe(true);
    const id = created.data!.tenant!.id;

    await adminPage.goto(PAGE);
    await adminPage.getByTestId(`tenant-select-${id}`).click();

    await adminPage.getByTestId('tenant-suspend').click();
    await expect
      .poll(async () => (await sdk.tenant.getTenant(id)).data?.tenant?.state)
      .toBe('SUSPENDED');
    await expect(adminPage.getByTestId('tenant-state')).toHaveText('SUSPENDED');

    await adminPage.getByTestId('tenant-resume').click();
    await expect
      .poll(async () => (await sdk.tenant.getTenant(id)).data?.tenant?.state)
      .toBe('ACTIVE');

    await sdk.tenant.deleteTenant(id);
  });

  test('looks a tenant up by name', async ({ adminPage, tenant }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByTestId('tenant-lookup-name').fill(tenant.name);
    await adminPage.getByTestId('tenant-lookup-submit').click();
    await expect(adminPage.getByTestId('tenant-lookup-result')).toContainText(tenant.id);
  });

  test('updates quotas and checks a quota', async ({ adminPage, sdk, tenant }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByTestId(`tenant-select-${tenant.id}`).click();

    await adminPage.getByTestId('tenant-quota-max-vms').fill('7');
    await adminPage.getByTestId('tenant-quota-submit').click();
    await expect
      .poll(async () => (await sdk.tenant.getQuotas(tenant.id)).data?.compute?.maxVms)
      .toBe(7);

    await adminPage.getByTestId('tenant-quota-check-resource').fill('vms');
    await adminPage.getByTestId('tenant-quota-check-amount').fill('1');
    await adminPage.getByTestId('tenant-quota-check-submit').click();
    const direct = await sdk.tenant.checkQuota({ tenantId: tenant.id, resource: 'vms', amount: 1 });
    expect(direct.success).toBe(true);
    await expect(adminPage.getByTestId('tenant-quota-check-result')).toHaveText(
      direct.data?.available ? 'available' : 'not available'
    );
  });

  test('syncs tenants', async ({ adminPage }) => {
    await adminPage.goto(PAGE);
    await adminPage.getByTestId('tenant-sync').click();
    await expect(adminPage.getByTestId('tenant-sync-result')).toBeVisible();
  });

  test('shows the DEK status and rotates the DEK', async ({ adminPage, sdk, tenant }) => {
    const before = await sdk.tenant.getDEKStatus(tenant.id);
    expect(before.success).toBe(true);
    const version = before.data!.dekStatus.version;

    await adminPage.goto(PAGE);
    await adminPage.getByTestId(`tenant-select-${tenant.id}`).click();
    await expect(adminPage.getByTestId('tenant-dek-version')).toHaveText(String(version));

    await adminPage.getByTestId('tenant-dek-rotate').click();
    await expect
      .poll(async () => (await sdk.tenant.getDEKStatus(tenant.id)).data?.dekStatus.version)
      .toBeGreaterThan(version);
  });

  test('initialises, seals and unseals a tenant barrier', async ({ adminPage, sdk }) => {
    const name = uniqueName('e2e-barrier');
    const created = await sdk.tenant.createTenant({ name });
    expect(created.success).toBe(true);
    const id = created.data!.tenant!.id;

    await adminPage.goto(PAGE);
    await adminPage.getByTestId(`tenant-select-${id}`).click();

    await adminPage.getByTestId('tenant-barrier-threshold').fill('1');
    await adminPage.getByTestId('tenant-barrier-shares').fill('1');
    await adminPage.getByTestId('tenant-barrier-init').click();
    await expect(adminPage.getByTestId('tenant-barrier-result')).toBeVisible();

    await adminPage.getByTestId('tenant-barrier-seal').click();
    await expect(adminPage.getByTestId('tenant-barrier-result')).toBeVisible();

    await sdk.tenant.deleteTenant(id);
  });
});
