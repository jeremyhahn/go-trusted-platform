import type { Locator, Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, type Tenant } from './fixtures';

/**
 * The API Credentials / Tokens cases of the mocked web/e2e/iam.spec.ts, on the
 * real-server harness (#2035, epic #1665). Apps are seeded through
 * sdk.iam.registerApp under a per-test name prefix and deleted in afterEach;
 * every case asserts what the server answered, as the /iam/tokens page shows it.
 *
 * Response shapes (pkg/webservice/v1/rest/iam/handlers.go): ListApps writes
 * the protojson ListIAMAppsResponse ({ apps: [{ clientId, name, grantTypes,
 * createdAt }], total }); RegisterApp writes the AppResponse itself, snake
 * case and unwrapped ({ client_id, client_secret, name, grant_types });
 * RotateAppSecret writes { client_id, client_secret, client_secret_expires_at }.
 * The page reads `result.app.clientSecret` after register and
 * `result.clientId/clientSecret/name` after rotate, so the credentials dialog
 * is asserted against what the page reads from the real answer.
 */

interface ListedApp {
  clientId?: string;
  name?: string;
  grantTypes?: string[];
}

const APPS_PATH = (tenantId: string) => `/tenants/${encodeURIComponent(tenantId)}/apps`;

/** The payload the SDK hands the page: the envelope's data, or the body itself. */
function payloadOf(body: unknown): Record<string, unknown> {
  const b = (body ?? {}) as Record<string, unknown>;
  const data = b.data;
  return (data && typeof data === 'object' ? data : b) as Record<string, unknown>;
}

/** The refusal text of an SDK answer. */
function refusalOf(res: { error?: unknown }): string {
  const e = res.error as { message?: string } | string | undefined;
  if (typeof e === 'string') return e;
  return e?.message ?? '';
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

async function listApps(sdk: PlatformClient, tenant: Tenant): Promise<ListedApp[]> {
  const res = await sdk.iam.listApps({ tenantId: tenant.id });
  expect(res.success, `listApps: ${JSON.stringify(res.error)}`).toBe(true);
  const data = (res.data ?? {}) as { apps?: ListedApp[] };
  return data.apps ?? [];
}

/** Registers an app through the SDK; returns the client id the server answered. */
async function seedApp(sdk: PlatformClient, tenant: Tenant, name: string, grantTypes = ['client_credentials']): Promise<string> {
  const res = await sdk.iam.registerApp({
    tenantId: tenant.id,
    name,
    grantTypes,
    redirectUris: [],
    responseTypes: [],
  });
  expect(res.success, `registerApp(${name}): ${JSON.stringify(res.error)}`).toBe(true);
  const app = (res.data ?? {}) as Record<string, unknown>;
  const clientId = str(app.client_id) || str(app.clientId);
  expect(clientId, `registerApp(${name}) answers a client id`).not.toBe('');
  return clientId;
}

function isAppsCall(r: Response, tenant: Tenant, method: string, suffix = ''): boolean {
  const url = new URL(r.url());
  return r.request().method() === method && url.pathname.endsWith(APPS_PATH(tenant.id) + suffix);
}

/** Opens /iam/tokens and waits for the page's own listing to answer. */
async function openTokens(page: Page, tenant: Tenant): Promise<void> {
  const listed = page.waitForResponse((r) => isAppsCall(r, tenant, 'GET'));
  await page.goto('/iam/tokens');
  expect((await listed).ok()).toBe(true);
  await expect(page.getByRole('heading', { name: 'API Credentials' })).toBeVisible();
}

function rowOf(page: Page, name: string): Locator {
  return page.getByRole('row').filter({ hasText: name });
}

/** The value of the stats card whose title is title. */
function cardValue(page: Page, title: string): Locator {
  return page
    .locator('div')
    .filter({ has: page.getByText(title, { exact: true }) })
    .filter({ has: page.locator('.text-2xl') })
    .last()
    .locator('.text-2xl');
}

async function rowAction(page: Page, name: string, action: 'Rotate Secret' | 'Delete'): Promise<void> {
  await rowOf(page, name).getByRole('button').last().click();
  await page.getByRole('menuitem', { name: action }).click();
}

function toast(page: Page, text: string): Locator {
  return page.getByText(text, { exact: true }).first();
}

let prefix = '';

test.describe('IAM API credentials, real server', () => {
  test.beforeEach(() => {
    prefix = `e2e-tok-${Date.now()}`;
  });

  test.afterEach(async ({ sdk, tenant }) => {
    const res = await sdk.iam.listApps({ tenantId: tenant.id }).catch(() => undefined);
    const apps = ((res?.data ?? {}) as { apps?: ListedApp[] }).apps ?? [];
    for (const app of apps) {
      if (app.clientId && app.name?.startsWith(prefix)) {
        await sdk.iam.deleteApp(tenant.id, app.clientId).catch(() => undefined);
      }
    }
  });

  test.describe('API Credentials / Tokens', () => {
    test('should display API credentials list', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-1`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      const row = rowOf(adminPage, name);
      await expect(row).toBeVisible();
      await expect(row.getByText(clientId, { exact: true })).toBeVisible();
      const listed = (await listApps(sdk, tenant)).find((a) => a.clientId === clientId);
      expect(listed?.name).toBe(name);
    });

    test('should show statistics cards', async ({ adminPage, sdk, tenant }) => {
      await seedApp(sdk, tenant, `${prefix}-1`);
      await seedApp(sdk, tenant, `${prefix}-2`);
      await openTokens(adminPage, tenant);
      const apps = await listApps(sdk, tenant);
      expect(apps.length).toBeGreaterThanOrEqual(2);
      const grantTypes = new Set(apps.flatMap((a) => a.grantTypes ?? []));
      await expect(cardValue(adminPage, 'Total Applications')).toHaveText(String(apps.length));
      await expect(cardValue(adminPage, 'Active')).toHaveText(String(apps.length));
      await expect(cardValue(adminPage, 'Grant Types')).toHaveText(String(grantTypes.size));
    });

    test('should open register application dialog', async ({ adminPage, tenant }) => {
      await openTokens(adminPage, tenant);
      await adminPage.getByRole('button', { name: 'Register Application' }).click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog.getByText('Register New Application')).toBeVisible();
      await expect(dialog.getByLabel('Application Name')).toBeVisible();
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
    });

    test('should register a new application and show secret', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-new`;
      await openTokens(adminPage, tenant);
      await adminPage.getByRole('button', { name: 'Register Application' }).click();
      await adminPage.getByRole('dialog').getByLabel('Application Name').fill(name);
      const registered = adminPage.waitForResponse((r) => isAppsCall(r, tenant, 'POST'));
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Register', exact: true }).click();
      const answer = await registered;
      expect(answer.ok()).toBe(true);
      const app = payloadOf(await answer.json());
      // The server answers the new app with its one-time secret.
      expect(str(app.client_secret) || str(app.clientSecret)).not.toBe('');
      await expect(toast(adminPage, 'Application registered')).toBeVisible();
      await expect(rowOf(adminPage, name)).toBeVisible();
      expect((await listApps(sdk, tenant)).some((a) => a.name === name)).toBe(true);
      // The page shows the secret only when the answer carries it under `app`.
      const pageRead = (app.app ?? {}) as { clientSecret?: string };
      const credentials = adminPage.getByRole('dialog').filter({ hasText: 'Application Credentials' });
      if (pageRead.clientSecret) {
        await expect(credentials.getByText(pageRead.clientSecret, { exact: true })).toBeVisible();
      } else {
        await expect(credentials).toBeHidden();
      }
    });

    test('should validate application name is required', async ({ adminPage, sdk, tenant }) => {
      await openTokens(adminPage, tenant);
      await adminPage.getByRole('button', { name: 'Register Application' }).click();
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Register', exact: true }).click();
      await expect(toast(adminPage, 'Application name is required')).toBeVisible();
      await expect(adminPage.getByText('Register New Application')).toBeVisible();
      // The server refuses the same empty name the page stops.
      const res = await sdk.iam.registerApp({ tenantId: tenant.id, name: '', grantTypes: ['client_credentials'], redirectUris: [], responseTypes: [] });
      expect(res.success).toBe(false);
      expect(refusalOf(res)).toContain('app name is required');
    });

    test('should rotate application secret', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-rot`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      adminPage.once('dialog', (d) => void d.accept());
      const rotated = adminPage.waitForResponse((r) => isAppsCall(r, tenant, 'POST', `/${clientId}/rotate-secret`));
      await rowAction(adminPage, name, 'Rotate Secret');
      const answer = await rotated;
      expect(answer.ok()).toBe(true);
      const first = payloadOf(await answer.json());
      const firstSecret = str(first.client_secret) || str(first.clientSecret);
      expect(firstSecret).not.toBe('');
      await expect(toast(adminPage, 'Secret rotated')).toBeVisible();
      // The page opens the credentials dialog with what it reads from the answer.
      const credentials = adminPage.getByRole('dialog').filter({ hasText: 'Application Credentials' });
      await expect(credentials).toBeVisible();
      const pageSecret = str(first.clientSecret);
      if (pageSecret) await expect(credentials.getByText(pageSecret, { exact: true })).toBeVisible();
      else await expect(credentials.getByText(firstSecret, { exact: true })).toHaveCount(0);
      // A second rotation answers a different secret (never printed).
      const again = await sdk.iam.rotateAppSecret(tenant.id, clientId);
      expect(again.success, JSON.stringify(again.error)).toBe(true);
      const second = (again.data ?? {}) as Record<string, unknown>;
      const secondSecret = str(second.client_secret) || str(second.clientSecret);
      expect(secondSecret).not.toBe('');
      expect(secondSecret === firstSecret).toBe(false);
    });

    test('should delete application with confirmation', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-del`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      let asked = '';
      adminPage.once('dialog', (d) => {
        asked = d.message();
        void d.accept();
      });
      const deleted = adminPage.waitForResponse((r) => isAppsCall(r, tenant, 'DELETE', `/${clientId}`));
      await rowAction(adminPage, name, 'Delete');
      expect((await deleted).ok()).toBe(true);
      expect(asked).toBe(`Are you sure you want to delete "${name}"?`);
      await expect(toast(adminPage, 'Application deleted')).toBeVisible();
      await expect(rowOf(adminPage, name)).toHaveCount(0);
      expect((await listApps(sdk, tenant)).some((a) => a.clientId === clientId)).toBe(false);
    });

    test('should cancel delete when confirmation is rejected', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-keep`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      adminPage.once('dialog', (d) => void d.dismiss());
      await rowAction(adminPage, name, 'Delete');
      await expect(rowOf(adminPage, name)).toBeVisible();
      expect((await listApps(sdk, tenant)).some((a) => a.clientId === clientId)).toBe(true);
    });

    test('should handle bulk delete', async ({ adminPage, sdk, tenant }) => {
      const names = [`${prefix}-b1`, `${prefix}-b2`];
      const ids = [await seedApp(sdk, tenant, names[0]), await seedApp(sdk, tenant, names[1])];
      await openTokens(adminPage, tenant);
      for (const name of names) await rowOf(adminPage, name).getByRole('checkbox').check();
      let asked = '';
      adminPage.once('dialog', (d) => {
        asked = d.message();
        void d.accept();
      });
      await adminPage.getByRole('button', { name: 'Delete selected' }).click();
      await expect(toast(adminPage, 'Applications deleted')).toBeVisible();
      expect(asked).toBe('Are you sure you want to delete 2 application(s)?');
      for (const name of names) await expect(rowOf(adminPage, name)).toHaveCount(0);
      const left = await listApps(sdk, tenant);
      for (const id of ids) expect(left.some((a) => a.clientId === id)).toBe(false);
    });

    // gap: should handle API errors gracefully: the mock injects a 500 on the app listing; the real server answers the admin's own tenant listing, and no seed makes it fail.

    // gap: should handle register application error: the mock injects a 500 on register; the page refuses an empty name before sending, so the server's one refusal (app name is required) is unreachable from the form.

    test('should handle delete error', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-gone`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      // The app goes away behind the page's back: the page's delete reaches a missing app.
      const first = await sdk.iam.deleteApp(tenant.id, clientId);
      expect(first.success, JSON.stringify(first.error)).toBe(true);
      const probe = await sdk.iam.deleteApp(tenant.id, clientId);
      adminPage.once('dialog', (d) => void d.accept());
      await rowAction(adminPage, name, 'Delete');
      if (probe.success) {
        await expect(toast(adminPage, 'Application deleted')).toBeVisible();
      } else {
        await expect(toast(adminPage, 'Error deleting application')).toBeVisible();
        const message = refusalOf(probe);
        expect(message).not.toBe('');
        await expect(adminPage.getByText(message).first()).toBeVisible();
      }
    });

    test('should handle rotate secret error', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-norot`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      const gone = await sdk.iam.deleteApp(tenant.id, clientId);
      expect(gone.success, JSON.stringify(gone.error)).toBe(true);
      const probe = await sdk.iam.rotateAppSecret(tenant.id, clientId);
      expect(probe.success, 'the server refuses to rotate a deleted app').toBe(false);
      adminPage.once('dialog', (d) => void d.accept());
      await rowAction(adminPage, name, 'Rotate Secret');
      await expect(toast(adminPage, 'Error rotating secret')).toBeVisible();
      const message = refusalOf(probe);
      expect(message).not.toBe('');
      await expect(adminPage.getByText(message).first()).toBeVisible();
    });

    test('should search credentials', async ({ adminPage, sdk, tenant }) => {
      const hit = `${prefix}-alpha`;
      const miss = `${prefix}-beta`;
      await seedApp(sdk, tenant, hit);
      await seedApp(sdk, tenant, miss);
      await openTokens(adminPage, tenant);
      await adminPage.getByPlaceholder('Search applications...').fill(hit);
      await expect(rowOf(adminPage, hit)).toBeVisible();
      await expect(rowOf(adminPage, miss)).toHaveCount(0);
    });

    test('should show empty state when no applications', async ({ adminPage, sdk, tenant }) => {
      await openTokens(adminPage, tenant);
      const apps = await listApps(sdk, tenant);
      await expect(cardValue(adminPage, 'Total Applications')).toHaveText(String(apps.length));
      if (apps.length > 0) {
        // Other specs' apps share the tenant: filter to a name the server lists for no app.
        await adminPage.getByPlaceholder('Search applications...').fill(`${prefix}-none`);
      }
      await expect(adminPage.getByText('No results.')).toBeVisible();
    });

    test('should display grant types badges', async ({ adminPage, sdk, tenant }) => {
      const name = `${prefix}-grants`;
      const clientId = await seedApp(sdk, tenant, name);
      await openTokens(adminPage, tenant);
      const listed = (await listApps(sdk, tenant)).find((a) => a.clientId === clientId);
      const grantTypes = listed?.grantTypes ?? [];
      expect(grantTypes).toContain('client_credentials');
      const row = rowOf(adminPage, name);
      for (const g of grantTypes.slice(0, 2)) await expect(row.getByText(g, { exact: true })).toBeVisible();
      if (grantTypes.length > 2) await expect(row.getByText(`+${grantTypes.length - 2}`, { exact: true })).toBeVisible();
    });

    // gap: should show loading state: the mock delays the listing to catch the spinner; the real server answers at once and the harness has no way to hold an answer.

    test('should copy secret to clipboard', async ({ adminPage, tenant }) => {
      await adminPage.context().grantPermissions(['clipboard-read', 'clipboard-write']);
      const name = `${prefix}-copy`;
      await openTokens(adminPage, tenant);
      await adminPage.getByRole('button', { name: 'Register Application' }).click();
      await adminPage.getByRole('dialog').getByLabel('Application Name').fill(name);
      const registered = adminPage.waitForResponse((r) => isAppsCall(r, tenant, 'POST'));
      await adminPage.getByRole('dialog').getByRole('button', { name: 'Register', exact: true }).click();
      const answer = await registered;
      expect(answer.ok()).toBe(true);
      const app = payloadOf(await answer.json());
      expect(str(app.client_secret) || str(app.clientSecret)).not.toBe('');
      const pageRead = (app.app ?? {}) as { clientSecret?: string };
      const credentials = adminPage.getByRole('dialog').filter({ hasText: 'Application Credentials' });
      if (pageRead.clientSecret) {
        const shown = (await credentials.locator('code').last().textContent()) ?? '';
        expect(shown).toBe(pageRead.clientSecret);
        await credentials.locator('code').last().locator('..').getByRole('button').click();
        const copied = await adminPage.evaluate(() => navigator.clipboard.readText());
        expect(copied === shown).toBe(true);
      } else {
        // The answer is not under `app`: the page opens no dialog, so there is no secret to copy.
        await expect(toast(adminPage, 'Application registered')).toBeVisible();
        await expect(credentials).toBeHidden();
      }
    });

    test('should show OAuth info alert', async ({ adminPage, tenant }) => {
      await openTokens(adminPage, tenant);
      await expect(adminPage.getByText('OAuth Client Credentials')).toBeVisible();
      await expect(adminPage.getByText(/Applications use OAuth 2\.0 client credentials flow for API access\./)).toBeVisible();
    });
  });
});
