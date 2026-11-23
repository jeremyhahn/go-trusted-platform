import { type Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect, type Tenant } from './fixtures';

/**
 * The Applications cases of the mocked web/e2e/iam.spec.ts, ported to the
 * real-server harness (#2035, epic #1665). Every application is registered
 * through sdk.iam.registerApp under a unique name and deleted in afterEach;
 * every assertion reads what the server answered (the SDK listing, the
 * response the page received, or the page state that answer produced).
 * A client secret is never read or printed.
 */

/** An application as ListApps sends it: proto IAMApp in protojson, camelCase. */
interface ListedApp {
  clientId?: string;
  name?: string;
  redirectUris?: string[];
  grantTypes?: string[];
}

let seq = 0;
function appName(): string {
  seq += 1;
  return `e2e-app-${Date.now()}-${seq}`;
}

/** Registers an app; returns the client ID the server assigned. */
async function registerApp(
  sdk: PlatformClient,
  tenant: Tenant,
  name: string,
  opts: { redirectUris?: string[]; grantTypes?: string[] } = {},
): Promise<string> {
  const res = await sdk.iam.registerApp({ tenantId: tenant.id, name, ...opts });
  if (!res.success || !res.data) throw new Error(`[real-server] registerApp(${name}): ${JSON.stringify(res.error)}`);
  // RegisterApp answers the AppResponse itself (snake_case), not the
  // { app } wrapper the SDK type declares.
  const clientId = (res.data as unknown as { client_id?: string }).client_id;
  if (!clientId) throw new Error(`[real-server] registerApp(${name}) answered no client_id`);
  return clientId;
}

/** The apps the server lists for the tenant, as the page asks for them. */
async function listApps(sdk: PlatformClient, tenant: Tenant): Promise<ListedApp[]> {
  const res = await sdk.iam.listApps({ tenantId: tenant.id });
  if (!res.success || !res.data) throw new Error(`[real-server] listApps: ${JSON.stringify(res.error)}`);
  return ((res.data as unknown as { apps?: ListedApp[] }).apps ?? []);
}

async function listedApp(sdk: PlatformClient, tenant: Tenant, clientId: string): Promise<ListedApp> {
  const app = (await listApps(sdk, tenant)).find((a) => a.clientId === clientId);
  if (!app) throw new Error(`[real-server] listApps does not list ${clientId}`);
  return app;
}

async function openApps(page: Page): Promise<void> {
  await page.goto('/iam/apps');
  await expect(page.getByRole('heading', { name: 'Applications', exact: true })).toBeVisible();
}

function appRow(page: Page, name: string) {
  return page.getByRole('row', { name: new RegExp(name) });
}

async function openRowMenu(page: Page, name: string): Promise<void> {
  await appRow(page, name).getByRole('button').last().click();
}

/** The value of a stats card, found by its title. */
function statValue(page: Page, title: string) {
  return page.getByText(title, { exact: true }).locator('..').locator('..').locator('.text-2xl');
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

test.describe('IAM applications, real server', () => {
  test.describe('Applications', () => {
    let seeded: string[] = [];

    test.afterEach(async ({ sdk, tenant }) => {
      for (const clientId of seeded) {
        await sdk.iam.deleteApp(tenant.id, clientId).catch(() => undefined);
      }
      seeded = [];
    });

    async function seed(
      sdk: PlatformClient,
      tenant: Tenant,
      name: string,
      opts: { redirectUris?: string[]; grantTypes?: string[] } = {},
    ): Promise<string> {
      const clientId = await registerApp(sdk, tenant, name, opts);
      seeded.push(clientId);
      return clientId;
    }

    test('should display applications list', async ({ adminPage: page, sdk, tenant }) => {
      const names = [appName(), appName(), appName()];
      for (const n of names) await seed(sdk, tenant, n);
      const listed = (await listApps(sdk, tenant)).map((a) => a.name);
      for (const n of names) expect(listed).toContain(n);

      await openApps(page);
      await expect(page.getByRole('columnheader', { name: /application name/i })).toBeVisible();
      await expect(page.getByRole('columnheader', { name: /client id/i })).toBeVisible();
      for (const n of names) await expect(page.getByText(n, { exact: true })).toBeVisible();
    });

    test('should show statistics cards', async ({ adminPage: page, sdk, tenant }) => {
      await seed(sdk, tenant, appName(), {
        redirectUris: ['https://app.example.com/cb1', 'https://app.example.com/cb2'],
      });
      await seed(sdk, tenant, appName(), { redirectUris: ['https://app.example.com/cb3'] });
      await seed(sdk, tenant, appName());
      const apps = await listApps(sdk, tenant);
      const total = apps.length;
      const withUris = apps.filter((a) => (a.redirectUris?.length ?? 0) > 0).length;
      const uris = apps.reduce((sum, a) => sum + (a.redirectUris?.length ?? 0), 0);

      await openApps(page);
      await expect(statValue(page, 'Total Applications')).toHaveText(String(total));
      await expect(statValue(page, 'With Redirect URIs')).toHaveText(String(withUris));
      await expect(statValue(page, 'Total Redirect URIs')).toHaveText(String(uris));
    });

    test('should open register application dialog', async ({ adminPage: page, sdk, tenant }) => {
      // The console registers on its own page, /iam/apps/new, not in a dialog.
      await openApps(page);
      await page.getByRole('button', { name: /register application/i }).click();
      await expect(page).toHaveURL(/\/iam\/apps\/new/);
      await expect(page.getByLabel('Application Name *')).toBeVisible();

      const name = appName();
      await page.getByLabel('Application Name *').fill(name);
      const answer = page.waitForResponse(
        (r) => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(`/tenants/${tenant.id}/apps`),
      );
      await page.getByRole('button', { name: 'Register Application', exact: true }).click();
      expect((await answer).ok()).toBe(true);
      const created = (await listApps(sdk, tenant)).find((a) => a.name === name);
      expect(created?.clientId).toBeTruthy();
      seeded.push(created!.clientId!);

      await expect(page.getByText('Application registered').first()).toBeVisible();
      await expect(page).toHaveURL(/\/iam\/apps\/?$/);
      await expect(page.getByText(name, { exact: true })).toBeVisible();
    });

    test('should show empty state when no applications', async ({ adminPage: page, sdk, tenant }) => {
      // The harness tenant is shared by every spec; the page must show what the
      // server lists for it: the empty table when it lists none.
      const total = (await listApps(sdk, tenant)).length;
      await openApps(page);
      await expect(statValue(page, 'Total Applications')).toHaveText(String(total));
      if (total === 0) {
        await expect(page.getByText(/no results/i)).toBeVisible();
      } else {
        await expect(page.locator('tbody tr')).toHaveCount(Math.min(total, 25));
      }
    });

    test('should show application row actions', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      await seed(sdk, tenant, name);
      await openApps(page);
      await expect(appRow(page, name)).toBeVisible();
      await openRowMenu(page, name);
      await expect(page.getByRole('menuitem', { name: /view/i })).toBeVisible();
      await expect(page.getByRole('menuitem', { name: /edit/i })).toBeVisible();
      await expect(page.getByRole('menuitem', { name: /rotate secret/i })).toBeVisible();
      await expect(page.getByRole('menuitem', { name: /delete/i })).toBeVisible();
    });

    test('should navigate to application details on view', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name, { redirectUris: ['https://app.example.com/view'] });
      await openApps(page);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: /view/i }).click();
      await expect(page).toHaveURL(new RegExp(`/iam/apps/${escapeRe(clientId)}`));

      // The static export serves the detail route as /__placeholder__/; the
      // console reaches a real app the way attest-cert-record.spec.ts does.
      await page.goto('/iam/apps/__placeholder__/');
      await expect(page.getByText(/error loading application/i)).toBeVisible();
      await page.evaluate((id) => window.history.pushState(null, '', `/iam/apps/${id}/`), clientId);
      await expect(page.getByText(name, { exact: true })).toBeVisible();
      await expect(page.getByText('https://app.example.com/view', { exact: true })).toBeVisible();
    });

    test('should delete application with confirmation', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      await openApps(page);
      await openRowMenu(page, name);
      page.once('dialog', (d) => d.accept());
      const answer = page.waitForResponse(
        (r) => r.request().method() === 'DELETE' && r.url().includes(encodeURIComponent(clientId)),
      );
      await page.getByRole('menuitem', { name: /delete/i }).click();
      expect((await answer).ok()).toBe(true);

      await expect(page.getByText('Application deleted').first()).toBeVisible();
      await expect(appRow(page, name)).toHaveCount(0);
      expect((await listApps(sdk, tenant)).some((a) => a.clientId === clientId)).toBe(false);
    });

    test('should cancel delete when confirmation is declined', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      await openApps(page);
      await openRowMenu(page, name);
      let deletes = 0;
      page.on('request', (r) => {
        if (r.method() === 'DELETE') deletes += 1;
      });
      page.once('dialog', (d) => d.dismiss());
      await page.getByRole('menuitem', { name: /delete/i }).click();

      await expect(appRow(page, name)).toBeVisible();
      expect(deletes).toBe(0);
      expect((await listApps(sdk, tenant)).some((a) => a.clientId === clientId)).toBe(true);
    });

    test('should select multiple applications with checkboxes', async ({ adminPage: page, sdk, tenant }) => {
      const gone = [appName(), appName()];
      const keep = appName();
      const goneIds = [await seed(sdk, tenant, gone[0]), await seed(sdk, tenant, gone[1])];
      const keepId = await seed(sdk, tenant, keep);
      await openApps(page);
      for (const n of [...gone, keep]) await expect(appRow(page, n)).toBeVisible();

      for (const n of gone) await appRow(page, n).getByRole('checkbox').check();
      for (const n of gone) await expect(appRow(page, n).getByRole('checkbox')).toBeChecked();
      page.once('dialog', (d) => d.accept());
      await page.getByRole('button', { name: /delete selected/i }).click();

      await expect(page.getByText('Applications deleted').first()).toBeVisible();
      for (const n of gone) await expect(appRow(page, n)).toHaveCount(0);
      await expect(appRow(page, keep)).toBeVisible();
      const ids = (await listApps(sdk, tenant)).map((a) => a.clientId);
      for (const id of goneIds) expect(ids).not.toContain(id);
      expect(ids).toContain(keepId);
    });

    // gap: should handle API errors gracefully: the mock injects a 500 on the app listing; the real server answers a valid tenant's listing, so the "Error Loading Applications" alert and its Retry button cannot be produced.

    test('should handle delete API error', async ({ adminPage: page, sdk, tenant }) => {
      // A real refusal: the row is still on the page but the app is already
      // gone on the server when the console deletes it.
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      await openApps(page);
      await expect(appRow(page, name)).toBeVisible();
      const gone = await sdk.iam.deleteApp(tenant.id, clientId);
      expect(gone.success).toBe(true);

      await openRowMenu(page, name);
      page.once('dialog', (d) => d.accept());
      const answer = page.waitForResponse(
        (r) => r.request().method() === 'DELETE' && r.url().includes(encodeURIComponent(clientId)),
      );
      await page.getByRole('menuitem', { name: /delete/i }).click();
      const res = await answer;
      if (res.ok()) {
        // The server deletes idempotently: the console shows the success it answered.
        await expect(page.getByText('Application deleted').first()).toBeVisible();
      } else {
        await expect(page.getByText('Error deleting application').first()).toBeVisible();
      }
      await expect(appRow(page, name)).toHaveCount(0);
    });

    test('should search/filter applications', async ({ adminPage: page, sdk, tenant }) => {
      const a = appName();
      const b = appName();
      await seed(sdk, tenant, a);
      await seed(sdk, tenant, b);
      await openApps(page);
      await expect(appRow(page, a)).toBeVisible();
      await expect(appRow(page, b)).toBeVisible();

      const search = page.getByPlaceholder('Search applications...');
      await search.fill(b);
      await expect(appRow(page, b)).toBeVisible();
      await expect(appRow(page, a)).toHaveCount(0);

      await search.fill('');
      await expect(appRow(page, a)).toBeVisible();
      await expect(appRow(page, b)).toBeVisible();
    });

    test('should display grant types badges correctly', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name, {
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
      });
      const grants = (await listedApp(sdk, tenant, clientId)).grantTypes ?? [];
      await openApps(page);
      const row = appRow(page, name);
      await expect(row).toBeVisible();
      if (grants.length === 0) {
        await expect(row.getByText('—', { exact: true })).toBeVisible();
      }
      for (const g of grants.slice(0, 2)) {
        await expect(row.getByText(g.replace('_', ' '), { exact: true })).toBeVisible();
      }
      if (grants.length > 2) {
        await expect(row.getByText(`+${grants.length - 2}`, { exact: true })).toBeVisible();
      }
    });

    test('should handle row click navigation to details', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      await openApps(page);
      await page.getByText(name, { exact: true }).click();
      await expect(page).toHaveURL(new RegExp(`/iam/apps/${escapeRe(clientId)}`));
    });

    // gap: should show loading state: the mock delays the app listing to catch the spinner; the real server answers at once, so the loading state cannot be held.

    test('should show toast when rotate secret is clicked', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      await seed(sdk, tenant, name);
      await openApps(page);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: /rotate secret/i }).click();
      await expect(page.getByText('Feature coming soon').first()).toBeVisible();
    });

    test('should display client ID truncated in table', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      const shown = clientId.length > 16 ? `${clientId.slice(0, 16)}...` : clientId;
      await openApps(page);
      await expect(appRow(page, name).getByText(shown, { exact: true })).toBeVisible();
    });

    test('should display redirect URIs count', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name, {
        redirectUris: ['https://app.example.com/a', 'https://app.example.com/b', 'https://app.example.com/c'],
      });
      const count = (await listedApp(sdk, tenant, clientId)).redirectUris?.length ?? 0;
      expect(count).toBe(3);
      await openApps(page);
      await expect(appRow(page, name).getByRole('cell', { name: String(count), exact: true })).toBeVisible();
    });

    test('should navigate to edit on edit action', async ({ adminPage: page, sdk, tenant }) => {
      const name = appName();
      const clientId = await seed(sdk, tenant, name);
      await openApps(page);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: /edit/i }).click();
      await expect(page).toHaveURL(new RegExp(`/iam/apps/${escapeRe(clientId)}`));
    });
  });

  test.describe('Access Control', () => {
    // gap: should allow tenant members to view users: it needs a session of a tenant member that is not the admin; the harness signs in only its admin and cannot create a member session.

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/iam/apps');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });
});
