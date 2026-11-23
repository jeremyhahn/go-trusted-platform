/**
 * Real-server checks of the IAM applications and tokens pages (#2054): every
 * capability-gated control carries the answer the server gives through
 * `sdk.capabilities.list()`, the app detail page shows the app the server
 * holds, and RotateAppSecret through the SDK reaches the server's rotate route.
 */
import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, type Tenant } from './fixtures';

interface Result<T> {
  success: boolean;
  data?: T;
  error?: unknown;
}

interface SeededApp {
  clientId: string;
  name: string;
}

function suffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
}

function ok(res: Result<unknown>): void {
  expect(res.success, JSON.stringify(res.error)).toBe(true);
}

async function seedApp(
  sdk: PlatformClient,
  tenant: Tenant,
  label: string,
  grantTypes: string[] = ['client_credentials'],
): Promise<SeededApp> {
  const name = `${label} ${suffix()}`;
  const res = await sdk.iam.registerApp({ tenantId: tenant.id, name, grantTypes });
  ok(res);
  const clientId = res.data?.app.clientId as string;
  expect(clientId, 'client id').toBeTruthy();
  return { clientId, name };
}

function field(body: unknown, keys: string[]): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  for (const [k, v] of Object.entries(body as Record<string, unknown>)) {
    if (keys.includes(k) && typeof v === 'string' && v) return v;
  }
  for (const v of Object.values(body as Record<string, unknown>)) {
    const found = field(v, keys);
    if (found) return found;
  }
  return undefined;
}

/** The server's capability answer: op to enabled. */
async function offered(sdk: PlatformClient): Promise<Map<string, boolean>> {
  const res = await sdk.capabilities.list();
  ok(res);
  const caps = res.data?.capabilities ?? [];
  return new Map(caps.map((c) => [c.op, c.enabled] as [string, boolean]));
}

/** Every gated control on the page carries the server's answer for its op. */
async function expectGatedMatches(page: Page, caps: Map<string, boolean>): Promise<void> {
  const gated = page.locator('[data-capability-op]');
  await expect(gated.first()).toBeVisible();
  const count = await gated.count();
  expect(count, 'gated controls on the page').toBeGreaterThan(0);
  for (let i = 0; i < count; i++) {
    const el = gated.nth(i);
    const op = (await el.getAttribute('data-capability-op')) as string;
    await expect(el, op).toHaveAttribute('data-capability-enabled', String(caps.get(op) ?? false));
  }
}

test.describe('IAM apps and tokens against the server', () => {
  test("gated controls on /iam/tokens carry the server's capability answer", async ({ adminPage, sdk, tenant }) => {
    const app = await seedApp(sdk, tenant, 'e2e tokens caps');
    const caps = await offered(sdk);
    await adminPage.goto('/iam/tokens');
    await expect(adminPage.getByText(app.name).first()).toBeVisible();
    await expectGatedMatches(adminPage, caps);
  });

  test("gated controls on /iam/apps carry the server's capability answer", async ({ adminPage, sdk, tenant }) => {
    const app = await seedApp(sdk, tenant, 'e2e apps caps');
    const caps = await offered(sdk);
    await adminPage.goto('/iam/apps');
    await expect(adminPage.getByText(app.name).first()).toBeVisible();
    await expect(adminPage.getByRole('button', { name: /Register Application/ })).toHaveAttribute(
      'data-capability-op',
      'POST /api/v1/iam/tenants/{tenant}/apps',
    );
    await expectGatedMatches(adminPage, caps);
  });

  test('the app detail page shows the app the server holds', async ({ adminPage, sdk, tenant }) => {
    const app = await seedApp(sdk, tenant, 'e2e app detail');
    await adminPage.goto(`/iam/apps/${app.clientId}`);
    await expect(adminPage.getByText(app.name).first()).toBeVisible();
    const edit = adminPage.getByRole('button', { name: /Edit/ });
    await expect(edit).toBeDisabled();
    await expect(edit).toHaveAttribute(
      'title',
      'Not available: the embedded IAM backend does not implement App.Update yet',
    );
  });

  test("RotateAppSecret through the SDK reaches the server's rotate route", async ({ sdk, tenant }) => {
    const app = await seedApp(sdk, tenant, 'e2e app rotate');
    const res = await sdk.iam.rotateAppSecret(tenant.id, app.clientId);
    ok(res);
    const secret = field(res.data, ['clientSecret', 'client_secret']);
    expect(typeof secret).toBe('string');
    expect(secret).not.toBe('');
  });
});
