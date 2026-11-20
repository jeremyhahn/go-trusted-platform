/**
 * Real-server spec for coverage-matrix slice 17 (#2054): PlatformIAMService
 * Policy and App operations. State is seeded through the SDK client, never
 * through route mocks, and every assertion reads what the server returns.
 *
 * The embedded IAM backend has no Policy.Update, Policy.Validate,
 * Policy.Simulate or App.Update handler (upstream gap, #2024 Codex): those
 * controls are rendered disabled with the reason, and the spec asserts that
 * they stay disabled and that the server-side object is unchanged.
 */
import { test, expect } from './fixtures';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Wire = Record<string, any>;

function unique(prefix: string): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** The SDK returns ApiResponse<T>; the REST body may also nest the object. */
function unwrap(res: unknown, key: string): Wire {
  const r = (res ?? {}) as Wire;
  const body = (r.data ?? r) as Wire;
  return (body[key] ?? body) as Wire;
}

function policyYaml(name: string, tenantId: string, action = 'read'): string {
  return [
    'apiVersion: v1',
    'kind: Policy',
    'metadata:',
    `  name: ${name}`,
    `  tenant: ${tenantId}`,
    '  description: seeded by iam-policy.spec',
    'spec:',
    '  rules:',
    '    - name: rule-1',
    '      effect: allow',
    `      actions: [${action}]`,
    '      resources: ["*"]',
  ].join('\n');
}

test.describe('IAM policies (real server)', () => {
  test('CreatePolicy: the new-policy form creates a policy the server returns', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-create');
    await adminPage.goto('/iam/policies/new');
    await adminPage.getByLabel('Name *').fill(name);
    await adminPage.getByLabel('Description').fill('created through the UI');
    await adminPage.getByLabel('Actions (comma-separated)').fill('read, list');
    await adminPage.getByRole('button', { name: 'Create Policy' }).click();
    await expect(adminPage).toHaveURL(/\/iam\/policies$/);

    const policy = unwrap(await sdk.iam.getPolicy(tenant.id, name), 'policy');
    expect(policy.name).toBe(name);
    const spec = String(policy.spec_yaml ?? policy.specYaml ?? policy.spec ?? '');
    expect(spec).toContain('list');

    await sdk.iam.deletePolicy(tenant.id, name);
  });

  test('GetPolicy: the detail view shows the seeded policy and its spec', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-get');
    const yaml = policyYaml(name, tenant.id, 'write');
    await sdk.iam.createPolicy({
      tenantId: tenant.id,
      name,
      description: 'seeded by iam-policy.spec',
      specYaml: yaml,
      spec_yaml: yaml,
    });
    const served = unwrap(await sdk.iam.getPolicy(tenant.id, name), 'policy');
    expect(served.name).toBe(name);

    await adminPage.goto(`/iam/policies/${encodeURIComponent(name)}`);
    await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible();
    await expect(adminPage.getByText('seeded by iam-policy.spec').first()).toBeVisible();
    await expect(adminPage.locator('pre')).toContainText('write');

    await sdk.iam.deletePolicy(tenant.id, name);
  });

  test('UpdatePolicy: Edit is gated off with the reason and the policy is unchanged', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-update');
    const yaml = policyYaml(name, tenant.id);
    await sdk.iam.createPolicy({ tenantId: tenant.id, name, description: '', specYaml: yaml, spec_yaml: yaml });

    await adminPage.goto(`/iam/policies/${encodeURIComponent(name)}`);
    const edit = adminPage.getByRole('button', { name: 'Edit' });
    await expect(edit).toBeDisabled();
    await expect(edit).toHaveAccessibleDescription(/.+/);

    const after = unwrap(await sdk.iam.getPolicy(tenant.id, name), 'policy');
    expect(String(after.spec_yaml ?? after.specYaml ?? after.spec ?? '')).toContain('read');

    await sdk.iam.deletePolicy(tenant.id, name);
  });

  test('ValidatePolicy and TestPolicy: the policy test page gates both with the reason', async ({
    adminPage,
  }) => {
    await adminPage.goto('/iam/policies/test');
    await expect(adminPage.getByRole('heading', { name: 'Policy Test' })).toBeVisible();
    for (const label of ['Validate', 'Run Test']) {
      const button = adminPage.getByRole('button', { name: label });
      await expect(button).toBeDisabled();
      await expect(button).toHaveAccessibleDescription(/.+/);
    }
    await expect(adminPage.getByTestId('validate-result')).toHaveCount(0);
    await expect(adminPage.getByTestId('test-result')).toHaveCount(0);
  });
});

test.describe('IAM apps (real server)', () => {
  test('GetApp: the detail view shows the seeded app the server returns', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-app');
    const created = unwrap(
      await sdk.iam.registerApp({
        tenantId: tenant.id,
        name,
        redirectUris: ['https://app.example.test/callback'],
        grantTypes: ['authorization_code'],
      }),
      'app',
    );
    const clientId = String(created.client_id ?? created.clientId);
    expect(clientId).not.toBe('');

    const served = unwrap(await sdk.iam.getApp(tenant.id, clientId), 'app');
    expect(served.name).toBe(name);

    await adminPage.goto(`/iam/apps/${encodeURIComponent(clientId)}`);
    await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible();
    await expect(adminPage.getByText(clientId, { exact: true }).first()).toBeVisible();
    await expect(adminPage.getByText('https://app.example.test/callback')).toBeVisible();

    await sdk.iam.deleteApp(tenant.id, clientId);
  });

  test('UpdateApp: Edit is gated off with the reason and the app is unchanged', async ({
    adminPage,
    sdk,
    tenant,
  }) => {
    const name = unique('e2e-app-upd');
    const created = unwrap(
      await sdk.iam.registerApp({
        tenantId: tenant.id,
        name,
        redirectUris: ['https://app.example.test/cb'],
        grantTypes: ['authorization_code'],
      }),
      'app',
    );
    const clientId = String(created.client_id ?? created.clientId);

    await adminPage.goto(`/iam/apps/${encodeURIComponent(clientId)}`);
    const edit = adminPage.getByRole('button', { name: 'Edit' });
    await expect(edit).toBeDisabled();
    await expect(edit).toHaveAccessibleDescription(/.+/);

    const after = unwrap(await sdk.iam.getApp(tenant.id, clientId), 'app');
    expect(after.name).toBe(name);

    await sdk.iam.deleteApp(tenant.id, clientId);
  });
});
