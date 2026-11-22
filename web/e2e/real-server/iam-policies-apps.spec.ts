import { expect, test } from './fixtures';

/**
 * Real-server spec for the IAM policy and app pages (row #2054, epic #1665).
 *
 * Drives CreatePolicy, GetPolicy, UpdatePolicy, ValidatePolicy, TestPolicy,
 * GetApp and UpdateApp through the console against the real server: no
 * page.route, every answer comes from the API. Each gated control is checked
 * to be enabled by the server's capabilities.
 */

function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}`;
}

/** The REST wire carries the resource either bare or under a key. */
function unwrap(data: unknown, key: string): Record<string, unknown> {
  const raw = (data ?? {}) as Record<string, unknown>;
  return ((raw[key] as Record<string, unknown> | undefined) ?? raw) as Record<string, unknown>;
}

test.describe('IAM policies and apps (real server)', () => {
  test('creates a policy, views, validates and edits it', async ({ adminPage, sdk, tenant }) => {
    const name = unique('e2e-policy');

    // CreatePolicy
    await adminPage.goto('/iam/policies/new');
    await adminPage.getByLabel('Name *').fill(name);
    await adminPage.getByLabel('Description').fill('created by the real-server spec');
    const create = adminPage.getByRole('button', { name: 'Create Policy' });
    await expect(create).toHaveAttribute('data-capability-enabled', 'true');
    await create.click();
    await expect(adminPage).toHaveURL(/\/iam\/policies$/, { timeout: 15_000 });

    // GetPolicy
    await adminPage.goto(`/iam/policies/${encodeURIComponent(name)}`);
    await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    await expect(adminPage.getByText('created by the real-server spec')).toBeVisible();

    // ValidatePolicy
    const validate = adminPage.getByRole('button', { name: 'Validate', exact: true });
    await expect(validate).toHaveAttribute('data-capability-enabled', 'true');
    await validate.click();
    await expect(adminPage.getByText('Policy is valid')).toBeVisible({ timeout: 15_000 });

    // UpdatePolicy
    await adminPage.getByRole('button', { name: 'Edit' }).click();
    await adminPage.getByLabel('Description', { exact: true }).fill('edited by the real-server spec');
    const save = adminPage.getByRole('button', { name: 'Save', exact: true });
    await expect(save).toHaveAttribute('data-capability-enabled', 'true');
    await save.click();
    await expect(adminPage.getByText('edited by the real-server spec')).toBeVisible({ timeout: 15_000 });
    const got = await sdk.iam.getPolicy(tenant.id, name);
    expect(got.success).toBe(true);
    expect(unwrap(got.data, 'policy').description).toBe('edited by the real-server spec');
  });

  test('the policies Test card shows the server decision', async ({ adminPage }) => {
    // TestPolicy
    await adminPage.goto('/iam/policies');
    await adminPage.getByLabel('Subject').fill('e2e-subject');
    await adminPage.getByLabel('Action').fill('read');
    await adminPage.getByLabel('Resource').fill('kv://config/e2e');
    const run = adminPage.getByRole('button', { name: 'Run test' });
    await expect(run).toHaveAttribute('data-capability-enabled', 'true');
    await run.click();
    await expect(adminPage.getByRole('status').getByText(/^(Allowed|Denied)$/)).toBeVisible({ timeout: 15_000 });
  });

  test('opens an app and renames it', async ({ adminPage, sdk, tenant }) => {
    const name = unique('e2e-app');
    const registered = await sdk.iam.registerApp({
      tenantId: tenant.id,
      name,
      redirectUris: ['https://example.com/callback'],
      grantTypes: ['client_credentials'],
    } as Parameters<typeof sdk.iam.registerApp>[0]);
    expect(registered.success).toBe(true);
    const app = unwrap(registered.data, 'app');
    const clientId = String(app.client_id ?? app.clientId ?? '');
    expect(clientId).not.toBe('');

    // GetApp
    await adminPage.goto(`/iam/apps/${encodeURIComponent(clientId)}`);
    await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible({ timeout: 15_000 });

    // UpdateApp
    const renamed = `${name}-renamed`;
    await adminPage.getByLabel('Application name').fill(renamed);
    const save = adminPage.getByRole('button', { name: 'Save', exact: true });
    await expect(save).toHaveAttribute('data-capability-enabled', 'true');
    await save.click();
    await expect(adminPage.getByText(renamed, { exact: true }).first()).toBeVisible({ timeout: 15_000 });
    const got = await sdk.iam.getApp(tenant.id, clientId);
    expect(got.success).toBe(true);
    expect(unwrap(got.data, 'app').name).toBe(renamed);
  });
});
