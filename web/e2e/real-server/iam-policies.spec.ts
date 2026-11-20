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

test.describe('IAM policies and apps (#1728)', () => {
  test('ValidatePolicy reports the verdict the server gives', async ({ adminPage }) => {
    await adminPage.goto('/iam/policies/test');
    await expect(adminPage.getByRole('heading', { name: 'Policy Test' })).toBeVisible();

    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && /\/policies\/validate$/.test(new URL(r.url()).pathname)
    );
    await adminPage.getByRole('button', { name: 'Validate', exact: true }).click();
    const body = (await (await answer).json().catch(() => ({}))) as { valid?: boolean; errors?: string[] };

    if (body.valid) {
      await expect(adminPage.getByText('Policy is valid')).toBeVisible();
    } else {
      await expect(adminPage.getByText('Policy is invalid')).toBeVisible();
      for (const err of body.errors ?? []) {
        await expect(adminPage.getByText(err).first()).toBeVisible();
      }
    }
  });

  test('TestPolicy shows the decision the server makes', async ({ adminPage }) => {
    await adminPage.goto('/iam/policies/test');

    const run = adminPage.getByRole('button', { name: 'Run Test' });
    await expect(run).toBeDisabled();
    await adminPage.locator('#subject-id').fill('user-1');
    await adminPage.locator('#resource').fill('kv://config/a');
    await adminPage.locator('#roles').fill('admin, ops');

    const answer = adminPage.waitForResponse(
      (r) => r.request().method() === 'POST' && /\/policies\/test$/.test(new URL(r.url()).pathname)
    );
    await run.click();
    const res = await answer;
    const body = (await res.json().catch(() => ({}))) as {
      allowed?: boolean;
      matchedPolicy?: string;
      matched_policy?: string;
    };

    const result = adminPage.getByTestId('test-result');
    if (res.ok()) {
      await expect(result.getByText(body.allowed ? 'Allowed' : 'Denied').first()).toBeVisible();
      const matched = body.matchedPolicy ?? body.matched_policy;
      if (matched) {
        await expect(result.getByText(`Matched policy: ${matched}`)).toBeVisible();
      }
    } else {
      await expect(adminPage.getByText(/error|failed/i).first()).toBeVisible();
    }
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

  test('UpdatePolicy from the policy page, behind a confirm', async ({ adminPage, sdk, tenant }) => {
    const name = `allow-read-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'Read access');

    const dialogs: string[] = [];
    adminPage.on('dialog', (dialog) => {
      dialogs.push(dialog.message());
      void dialog.accept();
    });
    await adminPage.goto(`/iam/policies/${name}`);
    await expect(adminPage.getByText('Read access')).toBeVisible();

    await adminPage.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(adminPage.locator('#policy-description')).toBeVisible();
    await expect(adminPage.locator('#policy-yaml')).toHaveCount(0);
    await adminPage.locator('#policy-description').fill('Read access for operators');
    await adminPage.locator('#policy-priority').fill('20');
    await adminPage.getByRole('button', { name: 'Save', exact: true }).click();

    await expect(adminPage.getByText('Read access for operators')).toBeVisible();
    await expect(adminPage.getByText('priority 20')).toBeVisible();
    expect(dialogs).toEqual([`Save changes to policy "${name}"?`]);
    await expect
      .poll(async () => (await sdk.iam.getPolicy(tenant.id, name)).data?.policy)
      .toMatchObject({ description: 'Read access for operators', priority: 20 });
  });

  test('UpdatePolicy: dismissing the confirm changes nothing', async ({ adminPage, sdk, tenant }) => {
    const name = `allow-read-${suffix()}`;
    await createPolicyFromPage(adminPage, name, 'Read access');

    adminPage.on('dialog', (dialog) => void dialog.dismiss());
    await adminPage.goto(`/iam/policies/${name}`);
    await adminPage.getByRole('button', { name: 'Edit', exact: true }).click();
    await adminPage.locator('#policy-description').fill('Should not save');
    await adminPage.getByRole('button', { name: 'Save', exact: true }).click();
    await expect(adminPage.locator('#policy-description')).toBeVisible();

    expect((await sdk.iam.getPolicy(tenant.id, name)).data?.policy.description).toBe('Read access');
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

  test('UpdateApp from the app page, behind a confirm', async ({ adminPage, sdk, tenant }) => {
    const name = `Billing Portal ${suffix()}`;
    const created = await sdk.iam.registerApp({
      tenantId: tenant.id,
      name,
      redirectUris: ['app://billing/callback'],
      grantTypes: ['authorization_code'],
    });
    expect(created.success, JSON.stringify(created.error)).toBe(true);
    const clientId = created.data?.app.clientId as string;

    const dialogs: string[] = [];
    adminPage.on('dialog', (dialog) => {
      dialogs.push(dialog.message());
      void dialog.accept();
    });
    await adminPage.goto(`/iam/apps/${clientId}`);
    await expect(adminPage.getByText(name)).toBeVisible();

    await adminPage.getByRole('button', { name: 'Edit', exact: true }).click();
    await adminPage.locator('#app-name').fill(`Billing Console ${clientId}`);
    await adminPage.locator('#app-grant-types').fill('authorization_code, refresh_token');
    await adminPage.getByRole('button', { name: 'Save', exact: true }).click();

    await expect(adminPage.getByText('refresh_token')).toBeVisible();
    expect(dialogs).toEqual([`Save changes to application "${name}"?`]);
    await expect
      .poll(async () => (await sdk.iam.getApp(tenant.id, clientId)).data?.app)
      .toMatchObject({
        name: `Billing Console ${clientId}`,
        grantTypes: ['authorization_code', 'refresh_token'],
        redirectUris: ['app://billing/callback'],
      });
  });
});
