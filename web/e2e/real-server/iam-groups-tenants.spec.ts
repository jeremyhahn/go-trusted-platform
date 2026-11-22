/**
 * IAM groups, group members, permission check and tenants against the real
 * server (#2036, ported from the mocked iam-groups-tenants.spec.ts, slice 16
 * of #1665). State is seeded through the SDK and every assertion reads what
 * the server holds afterwards, not a recorded request.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';

/** The reason line EmbeddedIamGate renders (web/src/app/(dashboard)/iam/embedded-iam-gate.tsx). */
function gateReason(method: string): string {
  return `Not available: the embedded IAM backend does not implement ${method} yet`;
}

/** Records every non-GET request whose path the predicate accepts. */
function nonGetRequests(page: Page, matches: (pathname: string) => boolean): string[] {
  const sent: string[] = [];
  page.on('request', (r) => {
    if (r.method() !== 'GET' && matches(new URL(r.url()).pathname)) {
      sent.push(`${r.method()} ${r.url()}`);
    }
  });
  return sent;
}

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface Named {
  id?: string;
  groupId?: string;
  tenantId?: string;
  name?: string;
  description?: string;
  members?: string[];
}

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** The record a create or get answered with, whether wrapped or not. */
function record(res: Result<unknown>): Named {
  const data = (res.data ?? {}) as Named & { group?: Named; tenant?: Named };
  return data.group ?? data.tenant ?? data;
}

function ok(res: Result<unknown>): void {
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

test.describe('IAM groups, members, permission check and tenants', () => {
  test('CreateGroup from the new group page lands in the server', async ({ adminPage, sdk, tenant }) => {
    const name = `Operations-${suffix()}`;
    await adminPage.goto('/iam/groups/new');
    await adminPage.getByLabel(/name/i).first().fill(name);
    await adminPage.getByRole('button', { name: /create/i }).last().click();

    await expect
      .poll(async () => {
        const listed = await sdk.iam.listGroups({ tenantId: tenant.id });
        const groups = ((listed.data ?? {}) as { groups?: Named[] }).groups ?? [];
        return groups.map((g) => g.name);
      })
      .toContain(name);
  });

  test('GetGroup shows the group the server holds', async ({ adminPage, sdk, tenant }) => {
    const name = `Engineering-${suffix()}`;
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name, description: 'Builds things' });
    ok(created);
    const id = record(created).id ?? record(created).groupId;
    expect(id, 'group id').toBeTruthy();

    await adminPage.goto(`/iam/groups/${id}`);
    await expect(adminPage.getByText(name).first()).toBeVisible();
    await expect(adminPage.getByText('Builds things')).toBeVisible();
  });

  test('UpdateGroup from the detail page changes the server record', async ({ adminPage, sdk, tenant }) => {
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name: `Eng-${suffix()}`, description: 'Builds things' });
    ok(created);
    const id = (record(created).id ?? record(created).groupId) as string;
    const renamed = `Platform Engineering ${suffix()}`;

    await adminPage.goto(`/iam/groups/${id}`);
    await adminPage.getByLabel('Name', { exact: true }).fill(renamed);
    await adminPage.getByLabel('Description').fill('Runs the platform');
    await adminPage.getByRole('button', { name: 'Save group' }).click();

    await expect(adminPage.getByText(renamed).first()).toBeVisible();
    await expect
      .poll(async () => record(await sdk.iam.getGroup(tenant.id, id)))
      .toMatchObject({ name: renamed, description: 'Runs the platform' });
  });

  test('AddGroupMember and RemoveGroupMember are gated on the detail page', async ({ adminPage, sdk, tenant }) => {
    const created = await sdk.iam.createGroup({ tenantId: tenant.id, name: `Members-${suffix()}` });
    ok(created);
    const id = (record(created).id ?? record(created).groupId) as string;
    const user = `user-${suffix()}`;

    const sent = nonGetRequests(adminPage, (p) => p.includes(`/groups/${id}/members`));
    await adminPage.goto(`/iam/groups/${id}`);
    await adminPage.getByLabel('User ID', { exact: true }).fill(user);
    await expect(adminPage.getByRole('button', { name: 'Add member' })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('Group.AddMember'))).toBeVisible();

    await adminPage.getByLabel('User ID to remove').fill(user);
    await expect(adminPage.getByRole('button', { name: 'Remove by user ID' })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('Group.RemoveMember')).first()).toBeVisible();
    expect(sent).toEqual([]);
  });

  test('CheckPermission shows the decision the server makes', async ({ adminPage, sdk, tenant }) => {
    const decision = await sdk.iam.checkPermission({
      tenantId: tenant.id,
      subjectId: 'user-alice',
      action: 'read',
      resource: 'devices',
    });
    ok(decision);
    const allowed = Boolean((decision.data as { allowed?: boolean } | undefined)?.allowed);

    await adminPage.goto('/iam/permissions');
    await adminPage.getByLabel('Subject ID').fill('user-alice');
    await adminPage.getByLabel('Action').fill('read');
    await adminPage.getByLabel('Resource').fill('devices');
    await adminPage.getByRole('button', { name: 'Check', exact: true }).click();

    await expect(adminPage.getByRole('status').getByText(allowed ? 'Allowed' : 'Denied')).toBeVisible();
  });

  test('ListTenants shows the tenants the server holds', async ({ adminPage, sdk }) => {
    const ids = [`acme-${suffix()}`, `globex-${suffix()}`];
    for (const id of ids) {
      ok(await sdk.iam.createTenant({ id, name: `Name ${id}` }));
    }

    await adminPage.goto('/iam/tenants');
    await expect(adminPage.getByRole('heading', { name: 'Tenants', exact: true })).toBeVisible();
    for (const id of ids) {
      await expect(adminPage.getByRole('button', { name: `View tenant ${id}` })).toBeVisible();
    }
  });

  test('CreateTenant from the page lands in the server', async ({ adminPage, sdk }) => {
    const id = `initech-${suffix()}`;
    await adminPage.goto('/iam/tenants');
    await adminPage.getByLabel('Tenant ID').fill(id);
    await adminPage.getByLabel('Tenant name').fill(`Initech ${id}`);
    await adminPage.getByRole('button', { name: 'Create tenant' }).click();

    await expect(adminPage.getByRole('cell', { name: `Initech ${id}` })).toBeVisible();
    await expect.poll(async () => (await sdk.iam.getTenant(id)).success).toBe(true);
  });

  test('Create tenant stays disabled without an ID', async ({ adminPage }) => {
    await adminPage.goto('/iam/tenants');
    await adminPage.getByLabel('Tenant name').fill('Initech');
    await expect(adminPage.getByRole('button', { name: 'Create tenant' })).toBeDisabled();
  });

  test('a duplicate tenant create keeps the form and shows the error', async ({ adminPage, sdk }) => {
    const id = `dup-${suffix()}`;
    ok(await sdk.iam.createTenant({ id, name: `First ${id}` }));

    await adminPage.goto('/iam/tenants');
    await adminPage.getByLabel('Tenant ID').fill(id);
    await adminPage.getByLabel('Tenant name').fill(`Second ${id}`);
    await adminPage.getByRole('button', { name: 'Create tenant' }).click();

    await expect(adminPage.getByText('Failed to create tenant').first()).toBeVisible();
    await expect(adminPage.getByLabel('Tenant name')).toHaveValue(`Second ${id}`);
    expect(record(await sdk.iam.getTenant(id)).name).toBe(`First ${id}`);
  });

  test('GetTenant and UpdateTenant from the tenant detail', async ({ adminPage, sdk }) => {
    const id = `acme-${suffix()}`;
    ok(await sdk.iam.createTenant({ id, name: `Acme ${id}` }));

    await adminPage.goto('/iam/tenants');
    await adminPage.getByRole('button', { name: `View tenant ${id}` }).click();
    await expect(adminPage.getByTestId('tenant-detail').getByText(`Acme ${id}`)).toBeVisible();

    await adminPage.getByLabel('New name').fill(`Acme Industries ${id}`);
    await adminPage.getByRole('button', { name: 'Save tenant' }).click();
    await expect(adminPage.getByRole('cell', { name: `Acme Industries ${id}` })).toBeVisible();
    await expect.poll(async () => record(await sdk.iam.getTenant(id)).name).toBe(`Acme Industries ${id}`);
  });

  test('DeleteTenant behind a confirm; cancel keeps the tenant', async ({ adminPage, sdk }) => {
    const id = `globex-${suffix()}`;
    ok(await sdk.iam.createTenant({ id, name: `Globex ${id}` }));

    await adminPage.goto('/iam/tenants');
    await adminPage.getByRole('button', { name: `Delete tenant ${id}` }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Delete tenant?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect((await sdk.iam.getTenant(id)).success).toBe(true);

    await adminPage.getByRole('button', { name: `Delete tenant ${id}` }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Delete tenant' }).click();
    await expect(adminPage.getByRole('cell', { name: `Globex ${id}` })).toHaveCount(0);
    await expect.poll(async () => (await sdk.iam.getTenant(id)).success).toBe(false);
  });

  test('ListTenants pages by limit and offset past the first 50', async ({ adminPage, sdk }) => {
    const first = await sdk.iam.listTenants({ pageSize: 50 });
    ok(first);
    const tag = suffix();
    const have = ((first.data ?? {}) as { tenants?: Named[]; total?: number }).tenants?.length ?? 0;
    for (let i = have; i < 51; i++) {
      ok(await sdk.iam.createTenant({ id: `t-${tag}-${i}`, name: `Tenant ${tag} ${i}` }));
    }

    await adminPage.goto('/iam/tenants');
    await expect(adminPage.getByText(/Page 1 of \d+/)).toBeVisible();
    await expect(adminPage.getByTestId('tenants-prev')).toBeDisabled();

    const second = adminPage.waitForRequest(
      (r) => r.method() === 'GET' && /\/tenants\?/.test(r.url()) && new URL(r.url()).searchParams.get('offset') === '50'
    );
    await adminPage.getByTestId('tenants-next').click();
    const req = await second;
    expect(new URL(req.url()).searchParams.get('limit')).toBe('50');
    await expect(adminPage.getByText(/Page 2 of \d+/)).toBeVisible();
  });
});
