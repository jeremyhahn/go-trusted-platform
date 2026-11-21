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

  // #2146 Codex P1: the embedded IAM backend has no Validate or Simulate
  // handler, so EmbeddedIamGate renders both controls disabled with a reason.
  test('ValidatePolicy: Validate is disabled on the embedded backend and sends nothing', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/policies/test');
    await expect(page.getByRole('heading', { name: 'Policy Test' })).toBeVisible();

    await expect(page.getByRole('button', { name: 'Validate', exact: true })).toBeDisabled();
    await expect(
      page.getByText('Not available: the embedded IAM backend does not implement Policy.Validate yet').first()
    ).toBeVisible();
    expect(api.find('POST', '/policies/validate')).toHaveLength(0);
  });

  test('TestPolicy: Run Test is disabled on the embedded backend and sends nothing', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/policies/test');
    await expect(page.getByRole('heading', { name: 'Policy Test' })).toBeVisible();

    await expect(page.getByRole('button', { name: 'Run Test' })).toBeDisabled();
    await expect(
      page.getByText('Not available: the embedded IAM backend does not implement Policy.Simulate yet').first()
    ).toBeVisible();
    expect(api.find('POST', '/policies/test')).toHaveLength(0);
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

  test('UpdatePolicy: Edit is disabled on the embedded backend and sends nothing', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/policies/allow-read');
    await expect(page.getByText('Read access')).toBeVisible();

    await expect(page.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
    await expect(
      page.getByText('Not available: the embedded IAM backend does not implement Policy.Update yet').first()
    ).toBeVisible();
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

  test('UpdateApp: Edit is disabled on the embedded backend and sends nothing', async ({ page }) => {
    const api = await setup(page);
    await page.goto('/iam/apps/client-1');
    await expect(page.getByText('Billing Portal')).toBeVisible();

    await expect(page.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
    await expect(
      page.getByText('Not available: the embedded IAM backend does not implement App.Update yet').first()
    ).toBeVisible();
    expect(api.find('PUT', '/apps/client-1')).toHaveLength(0);
  });
});
