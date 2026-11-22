/**
 * IAM policies and apps against the real server (#2036, ported from the
 * mocked iam-policies.spec.ts, #1728). Policies are created from the new
 * policy page and apps through the SDK; every assertion reads what the
 * server holds or answers.
 */
import type { Page } from '@playwright/test';
import { test, expect } from './fixtures';

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

/** Creates a policy from the new policy page and waits for the list page. */
async function createPolicyFromPage(page: Page, name: string, description: string): Promise<void> {
  await page.goto('/iam/policies/new');
  await page.locator('#name').fill(name);
  await page.locator('#description').fill(description);
  await page.getByRole('button', { name: 'Create Policy' }).click();
  await expect(page).toHaveURL(/\/iam\/policies$/);
}

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

test.describe('IAM policies and apps (#1728)', () => {
  test('ValidatePolicy is gated: the embedded backend has no Policy.Validate', async ({ adminPage }) => {
    const sent = nonGetRequests(adminPage, (p) => /\/policies\/validate$/.test(p));
    await adminPage.goto('/iam/policies/test');
    await expect(adminPage.getByRole('heading', { name: 'Policy Test' })).toBeVisible();

    await expect(adminPage.getByRole('button', { name: 'Validate', exact: true })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('Policy.Validate'))).toBeVisible();
    expect(sent).toEqual([]);
  });

  test('TestPolicy is gated: the embedded backend has no Policy.Simulate', async ({ adminPage }) => {
    const sent = nonGetRequests(adminPage, (p) => /\/policies\/test$/.test(p));
    await adminPage.goto('/iam/policies/test');

    await adminPage.locator('#subject-id').fill('user-1');
    await adminPage.locator('#resource').fill('kv://config/a');
    await adminPage.locator('#roles').fill('admin, ops');
    await expect(adminPage.getByRole('button', { name: 'Run Test' })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('Policy.Simulate'))).toBeVisible();
    expect(sent).toEqual([]);
  });

  test('CreatePolicy from the new policy page lands in the server', async ({ adminPage, sdk, tenant }) => {
    const name = `deny-write-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'No writes');

    const got = await sdk.iam.getPolicy(tenant.id, name);
    expect(got.success, JSON.stringify(got.error)).toBe(true);
    expect(got.data?.policy).toMatchObject({ name, description: 'No writes' });
  });

  test('GetPolicy shows the policy the server holds', async ({ adminPage, sdk, tenant }) => {
    const name = `allow-read-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'Read access');
    const got = await sdk.iam.getPolicy(tenant.id, name);
    expect(got.success, JSON.stringify(got.error)).toBe(true);

    await adminPage.goto(`/iam/policies/${name}`);
    await expect(adminPage.getByText('Read access')).toBeVisible();
    await expect(adminPage.getByText(`priority ${got.data?.policy.priority ?? 0}`)).toBeVisible();
    await expect(adminPage.getByText('kind: Policy')).toBeVisible();
  });

  test('UpdatePolicy is gated: Edit is disabled with the reason shown', async ({ adminPage, sdk, tenant }) => {
    const name = `allow-read-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'Read access');

    const sent = nonGetRequests(adminPage, (p) => p.endsWith(`/policies/${name}`));
    await adminPage.goto(`/iam/policies/${name}`);
    await expect(adminPage.getByText('Read access')).toBeVisible();

    await expect(adminPage.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('Policy.Update'))).toBeVisible();
    await expect(adminPage.locator('#policy-description')).toHaveCount(0);
    expect(sent).toEqual([]);
    expect((await sdk.iam.getPolicy(tenant.id, name)).data?.policy.description).toBe('Read access');
  });

  test('UpdatePolicy is gated: the policy the server holds stays unchanged', async ({ adminPage, sdk, tenant }) => {
    const name = `allow-read-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'Read access');
    const before = (await sdk.iam.getPolicy(tenant.id, name)).data?.policy;

    const sent = nonGetRequests(adminPage, (p) => p.endsWith(`/policies/${name}`));
    await adminPage.goto(`/iam/policies/${name}`);
    await expect(adminPage.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
    await expect(adminPage.getByRole('button', { name: 'Save', exact: true })).toHaveCount(0);

    expect(sent).toEqual([]);
    expect((await sdk.iam.getPolicy(tenant.id, name)).data?.policy).toMatchObject({
      description: before?.description,
      priority: before?.priority,
    });
  });

  test('GetApp shows the app the server holds', async ({ adminPage, sdk, tenant }) => {
    const name = `Billing Portal ${suffix()}`;
    const created = await sdk.iam.registerApp({
      tenantId: tenant.id,
      name,
      redirectUris: ['app://billing/callback'],
      grantTypes: ['authorization_code'],
    });
    expect(created.success, JSON.stringify(created.error)).toBe(true);
    const clientId = created.data?.app.clientId as string;
    expect(clientId, 'client id').toBeTruthy();

    await adminPage.goto(`/iam/apps/${clientId}`);
    await expect(adminPage.getByText(name)).toBeVisible();
    await expect(adminPage.getByText('authorization_code')).toBeVisible();
    await expect(adminPage.getByText('app://billing/callback')).toBeVisible();
  });

  test('UpdateApp is gated: Edit is disabled with the reason shown', async ({ adminPage, sdk, tenant }) => {
    const name = `Billing Portal ${suffix()}`;
    const created = await sdk.iam.registerApp({
      tenantId: tenant.id,
      name,
      redirectUris: ['app://billing/callback'],
      grantTypes: ['authorization_code'],
    });
    expect(created.success, JSON.stringify(created.error)).toBe(true);
    const clientId = created.data?.app.clientId as string;

    const sent = nonGetRequests(adminPage, (p) => p.endsWith(`/apps/${clientId}`));
    await adminPage.goto(`/iam/apps/${clientId}`);
    await expect(adminPage.getByText(name)).toBeVisible();

    await expect(adminPage.getByRole('button', { name: 'Edit', exact: true })).toBeDisabled();
    await expect(adminPage.getByText(gateReason('App.Update'))).toBeVisible();
    await expect(adminPage.locator('#app-name')).toHaveCount(0);
    expect(sent).toEqual([]);
    expect((await sdk.iam.getApp(tenant.id, clientId)).data?.app).toMatchObject({
      name,
      grantTypes: ['authorization_code'],
      redirectUris: ['app://billing/callback'],
    });
  });
});
