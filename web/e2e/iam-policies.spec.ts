import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import {
  mockTenantApi,
  mockIAMPolicyAppApi,
  IAMPolicyAppApiMockConfig,
  MockIAMPolicy,
  MockIAMApp,
} from './fixtures/api-mock';

const POLICY: MockIAMPolicy = {
  name: 'allow-read',
  description: 'Read access',
  priority: 10,
  spec_yaml: 'apiVersion: v1\nkind: Policy\nmetadata:\n  name: allow-read',
};

const APP: MockIAMApp = {
  client_id: 'client-1',
  name: 'Billing Portal',
  redirect_uris: ['app://billing/callback'],
  grant_types: ['authorization_code'],
};

async function setup(page: Page, config: IAMPolicyAppApiMockConfig = {}) {
  await mockTenantApi(page);
  return mockIAMPolicyAppApi(page, { policies: [POLICY], apps: [APP], ...config });
}

test.describe('IAM policies and apps (#1728)', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('ValidatePolicy: POST /policies/validate from the policy test page', async ({ page }) => {
    const api = await setup(page, {
      validateResponse: { valid: false, errors: ['rule-1: unknown effect "maybe"'] },
    });
    await page.goto('/iam/policies/test');
    await expect(page.getByRole('heading', { name: 'Policy Test' })).toBeVisible();

    await page.getByRole('button', { name: 'Validate', exact: true }).click();

    await expect(page.getByText('Policy is invalid')).toBeVisible();
    await expect(page.getByText('rule-1: unknown effect "maybe"')).toBeVisible();
    const calls = api.find('POST', '/policies/validate');
    expect(calls).toHaveLength(1);
    expect(String(calls[0].body?.spec_yaml)).toContain('kind: Policy');
  });

  test('ValidatePolicy: a valid document is reported valid', async ({ page }) => {
    await setup(page, { validateResponse: { valid: true } });
    await page.goto('/iam/policies/test');
    await page.getByRole('button', { name: 'Validate', exact: true }).click();
    await expect(page.getByText('Policy is valid')).toBeVisible();
  });

  test('TestPolicy: POST /policies/test from the policy test page', async ({ page }) => {
    const api = await setup(page, {
      testResponse: { allowed: true, matchedPolicy: 'allow-read', matchedRule: 'rule-1' },
    });
    await page.goto('/iam/policies/test');

    const run = page.getByRole('button', { name: 'Run Test' });
    await expect(run).toBeDisabled();
    await page.locator('#subject-id').fill('user-1');
    await page.locator('#resource').fill('kv://config/a');
    await page.locator('#roles').fill('admin, ops');
    await run.click();

    const result = page.getByTestId('test-result');
    await expect(result.getByText('Allowed')).toBeVisible();
    await expect(result.getByText('Matched policy: allow-read')).toBeVisible();
    await expect(result.getByText('Matched rule: rule-1')).toBeVisible();
    const calls = api.find('POST', '/policies/test');
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({
      subjectId: 'user-1',
      action: 'read',
      resource: 'kv://config/a',
      roles: ['admin', 'ops'],
      groups: [],
    });
  });

  test('CreatePolicy: POST /policies from the new policy page', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/policies/new');

    await page.locator('#name').fill('deny-write');
    await page.locator('#description').fill('No writes');
    await page.getByRole('button', { name: 'Create Policy' }).click();

    await expect(page).toHaveURL(/\/iam\/policies$/);
    const calls = api.find('POST', '/policies');
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({ name: 'deny-write', description: 'No writes' });
    expect(String(calls[0].body?.spec_yaml)).toContain('name: deny-write');
  });

  test('GetPolicy: GET /policies/{id} on the policy page', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/policies/allow-read');

    await expect(page.getByText('Read access')).toBeVisible();
    await expect(page.getByText('priority 10')).toBeVisible();
    await expect(page.getByText('kind: Policy')).toBeVisible();
    expect(api.find('GET', '/policies/allow-read').length).toBeGreaterThan(0);
  });

  test('UpdatePolicy: PUT /policies/{id} from the policy page, behind a confirm', async ({ page }) => {
    const api = await setup(page);
    const dialogs: string[] = [];
    page.on('dialog', (dialog) => {
      dialogs.push(dialog.message());
      void dialog.accept();
    });
    await page.goto('/iam/policies/allow-read');
    await expect(page.getByText('Read access')).toBeVisible();

    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.locator('#policy-description').fill('Read access for operators');
    await page.locator('#policy-priority').fill('20');
    await page.getByRole('button', { name: 'Save', exact: true }).click();

    await expect(page.getByText('Read access for operators')).toBeVisible();
    await expect(page.getByText('priority 20')).toBeVisible();
    expect(dialogs).toEqual(['Save changes to policy "allow-read"?']);
    const calls = api.find('PUT', '/policies/allow-read');
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({
      policyName: 'allow-read',
      description: 'Read access for operators',
      priority: 20,
    });
  });

  test('UpdatePolicy: dismissing the confirm sends nothing', async ({ page }) => {
    const api = await setup(page);
    page.on('dialog', (dialog) => void dialog.dismiss());
    await page.goto('/iam/policies/allow-read');
    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(page.locator('#policy-description')).toBeVisible();
    expect(api.find('PUT', '/policies/allow-read')).toHaveLength(0);
  });

  test('GetApp: GET /apps/{id} on the app page', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/apps/client-1');

    await expect(page.getByText('Billing Portal')).toBeVisible();
    await expect(page.getByText('authorization_code')).toBeVisible();
    await expect(page.getByText('app://billing/callback')).toBeVisible();
    expect(api.find('GET', '/apps/client-1').length).toBeGreaterThan(0);
  });

  test('UpdateApp: PUT /apps/{id} from the app page, behind a confirm', async ({ page }) => {
    const api = await setup(page);
    const dialogs: string[] = [];
    page.on('dialog', (dialog) => {
      dialogs.push(dialog.message());
      void dialog.accept();
    });
    await page.goto('/iam/apps/client-1');
    await expect(page.getByText('Billing Portal')).toBeVisible();

    await page.getByRole('button', { name: 'Edit', exact: true }).click();
    await page.locator('#app-name').fill('Billing Console');
    await page.locator('#app-grant-types').fill('authorization_code, refresh_token');
    await page.getByRole('button', { name: 'Save', exact: true }).click();

    await expect(page.getByText('refresh_token')).toBeVisible();
    expect(dialogs).toEqual(['Save changes to application "Billing Portal"?']);
    const calls = api.find('PUT', '/apps/client-1');
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toMatchObject({
      clientId: 'client-1',
      name: 'Billing Console',
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: ['app://billing/callback'],
    });
  });
});
