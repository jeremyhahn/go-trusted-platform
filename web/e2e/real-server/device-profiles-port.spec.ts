import type { Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * Device Profiles against the real server (#2035, epic #1665): the port of the
 * mocked Device Profiles describe of web/e2e/devices.spec.ts. Profiles are
 * seeded through sdk.device.createProfile and deleted in afterEach; every
 * case asserts what the server answered, as the console renders it.
 *
 * The server answers POST /api/v1/device/profiles with the profile itself
 * (201, profileToResponse) and GET with { profiles, pagination }
 * (rest_handlers.go CreateProfile, ListProfiles): read res.data as a record,
 * not as an SDK wrapper type.
 */

type ProfileSeed = Parameters<PlatformClient['device']['createProfile']>[0]['profile'];

interface Seeded {
  id: string;
  name: string;
}

/** Profile ids this test created; afterEach deletes them. */
let created: string[] = [];
let seq = 0;

function uniqueName(): string {
  seq += 1;
  return `e2e-prof-${Date.now()}-${seq}`;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null;
}

function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string }; message?: string } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? b?.message ?? '';
}

async function seed(sdk: PlatformClient, profile: Record<string, unknown>): Promise<Seeded> {
  const name = (profile.name as string | undefined) ?? uniqueName();
  const res = await sdk.device.createProfile({ profile: { ...profile, name } as unknown as ProfileSeed });
  if (!res.success || !isRecord(res.data)) {
    throw new Error(`[real-server] createProfile(${name}): ${JSON.stringify(res.error)}`);
  }
  const id = String((res.data as Record<string, unknown>).id);
  created.push(id);
  return { id, name };
}

/** The profiles the server lists on the page's own request (first page, default size). */
async function listed(sdk: PlatformClient): Promise<Record<string, unknown>[]> {
  const res = await sdk.device.listProfiles();
  if (!res.success || !isRecord(res.data)) {
    throw new Error(`[real-server] listProfiles: ${JSON.stringify(res.error)}`);
  }
  const profiles = (res.data as Record<string, unknown>).profiles;
  return Array.isArray(profiles) ? (profiles as Record<string, unknown>[]) : [];
}

async function cleanup(sdk: PlatformClient): Promise<void> {
  for (const id of created) {
    await sdk.device.deleteProfile(id).catch(() => undefined);
  }
  created = [];
}

async function openProfiles(page: Page, firstName?: string): Promise<void> {
  await page.goto('/devices/profiles');
  await expect(page.getByRole('heading', { name: 'Device Profiles' })).toBeVisible();
  if (firstName) {
    await expect(page.getByText(firstName, { exact: true })).toBeVisible();
  } else {
    await expect(page.getByText('Loading profiles...')).toHaveCount(0);
  }
}

function row(page: Page, name: string) {
  return page.getByRole('row').filter({ has: page.getByText(name, { exact: true }) });
}

async function openRowMenu(page: Page, name: string): Promise<void> {
  await row(page, name).getByRole('button', { name: 'Open menu' }).click();
}

function statValue(page: Page, title: string) {
  return page.getByText(title, { exact: true }).locator('xpath=../..').locator('.text-2xl');
}

test.describe('Device profiles, real server', () => {
  test.describe('Profile List', () => {
    test.afterEach(async ({ sdk }) => {
      await cleanup(sdk);
    });

    test('should display profiles list', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), model: 'Model-X1', role: 'server' });
      await openProfiles(adminPage, p.name);
      for (const header of ['Name', 'Model', 'Role', 'Networks', 'PCR Baseline', 'Updated', 'Actions']) {
        await expect(adminPage.getByRole('columnheader', { name: header })).toBeVisible();
      }
      const r = row(adminPage, p.name);
      await expect(r).toContainText('Model-X1');
      await expect(r.getByText('Server', { exact: true })).toBeVisible();
    });

    test('should show statistics cards', async ({ adminPage, sdk }) => {
      await seed(sdk, { name: uniqueName(), role: 'server' });
      await seed(sdk, { name: uniqueName(), role: 'workstation' });
      const last = await seed(sdk, { name: uniqueName(), role: 'iot' });
      const profiles = await listed(sdk);
      const byRole = (role: string) => profiles.filter((p) => p.role === role).length;
      await openProfiles(adminPage, last.name);
      await expect(statValue(adminPage, 'Total Profiles')).toHaveText(String(profiles.length));
      await expect(statValue(adminPage, 'Servers')).toHaveText(String(byRole('server')));
      await expect(statValue(adminPage, 'Workstations')).toHaveText(String(byRole('workstation')));
      await expect(statValue(adminPage, 'IoT Devices')).toHaveText(String(byRole('iot')));
    });

    test('should open create profile dialog', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      await adminPage.getByRole('button', { name: /create profile/i }).first().click();
      const dialog = adminPage.getByRole('dialog');
      await expect(dialog.getByText('Create Device Profile')).toBeVisible();
      await expect(dialog.getByLabel('Profile Name')).toBeVisible();
      await expect(dialog.getByLabel('Model')).toBeVisible();
    });

    test('should create a new profile', async ({ adminPage, sdk }) => {
      await openProfiles(adminPage);
      const name = uniqueName();
      await adminPage.getByRole('button', { name: /create profile/i }).first().click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Profile Name').fill(name);
      await dialog.getByLabel('Model').fill('Model-C1');
      const answer = adminPage.waitForResponse(
        (r) => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith('/device/profiles'),
      );
      await dialog.getByRole('button', { name: /create profile/i }).click();
      const res = await answer;
      const body: unknown = await res.json();
      expect(res.status(), serverMessage(body)).toBe(201);
      expect(isRecord(body) && body.name).toBe(name);
      if (isRecord(body)) created.push(String(body.id));
      expect(isRecord(body) && body.role).toBe('server');
      await expect(adminPage.getByText('Profile created', { exact: true })).toBeVisible();
      await expect(dialog).toBeHidden();
      const r = row(adminPage, name);
      await expect(r).toContainText('Model-C1');
      await expect(r.getByText('Server', { exact: true })).toBeVisible();
    });

    test('should filter profiles by role', async ({ adminPage, sdk }) => {
      const server = await seed(sdk, { name: uniqueName(), role: 'server' });
      const workstation = await seed(sdk, { name: uniqueName(), role: 'workstation' });
      const iot = await seed(sdk, { name: uniqueName(), role: 'iot' });
      await openProfiles(adminPage, iot.name);
      await expect(adminPage.getByText(server.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByText(workstation.name, { exact: true })).toBeVisible();
      await adminPage.locator('button').filter({ hasText: /all roles/i }).click();
      await adminPage.getByRole('option', { name: /^server$/i }).click();
      await expect(adminPage.getByText(server.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByText(workstation.name, { exact: true })).toHaveCount(0);
      await expect(adminPage.getByText(iot.name, { exact: true })).toHaveCount(0);
    });

    test('should search profiles', async ({ adminPage, sdk }) => {
      const a = await seed(sdk, { name: uniqueName(), role: 'server' });
      const b = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, b.name);
      await adminPage.getByPlaceholder('Search profiles...').fill(a.name);
      await expect(adminPage.getByText(a.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByText(b.name, { exact: true })).toHaveCount(0);
      await adminPage.getByPlaceholder('Search profiles...').fill(`${a.name}-none`);
      await expect(adminPage.getByText('No profiles match your filters')).toBeVisible();
    });

    test('should delete profile with confirmation', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      adminPage.once('dialog', (d) => {
        expect(d.message()).toBe(`Are you sure you want to delete "${p.name}"?`);
        void d.accept();
      });
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      await expect(adminPage.getByText('Profile deleted', { exact: true })).toBeVisible();
      await expect(adminPage.getByText(p.name, { exact: true })).toHaveCount(0);
      expect((await listed(sdk)).some((x) => String(x.id) === p.id)).toBe(false);
    });

    test('should duplicate profile', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), model: 'Model-D1', role: 'server' });
      await openProfiles(adminPage, p.name);
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /duplicate/i }).click();
      await expect(adminPage.getByText('Profile created', { exact: true })).toBeVisible();
      const copyName = `${p.name} (Copy)`;
      await expect(row(adminPage, copyName)).toContainText('Model-D1');
      const copy = (await listed(sdk)).find((x) => x.name === copyName);
      expect(copy, 'the server lists the duplicate').toBeTruthy();
      if (copy) created.push(String(copy.id));
      expect(copy?.model).toBe('Model-D1');
      expect(copy?.role).toBe('server');
    });

    // gap: should handle API errors gracefully: the mock injects a 500 on GET /device/profiles; the real server lists the profiles of the session's tenant and the harness cannot make that read fail
    // The harness tenant shares one daemon with every spec: this case asserts
    // the empty state when the server lists no profile, else one row per
    // profile the server lists.

    test('should show empty state when no profiles', async ({ adminPage, sdk }) => {
      const profiles = await listed(sdk);
      await openProfiles(adminPage);
      if (profiles.length === 0) {
        await expect(adminPage.getByText('No device profiles found')).toBeVisible();
      } else {
        await expect(adminPage.getByRole('row')).toHaveCount(profiles.length + 1);
        await expect(adminPage.getByText('No device profiles found')).toHaveCount(0);
      }
    });
  });

  test.describe('Profile Actions', () => {
    test.afterEach(async ({ sdk }) => {
      await cleanup(sdk);
    });

    // gap: should navigate to profile details: the branch has no web/src/app/(dashboard)/devices/profiles/[id] page; the case asserts the URL the row menu pushes, nothing the missing page would show
    test('should navigate to profile details', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /view details/i }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/profiles/${p.id}/?$`));
    });

    // gap: should navigate to edit profile: the branch has no web/src/app/(dashboard)/devices/profiles/[id]/edit page; the case asserts the URL the row menu pushes, nothing the missing page would show
    test('should navigate to edit profile', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /edit profile/i }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/profiles/${p.id}/edit/?$`));
    });

    test('should cancel delete when dialog is dismissed', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      adminPage.once('dialog', (d) => void d.dismiss());
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      await expect(adminPage.getByText(p.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByText('Profile deleted', { exact: true })).toHaveCount(0);
      expect((await listed(sdk)).some((x) => String(x.id) === p.id)).toBe(true);
    });

    test('should display network configurations in table', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, {
        name: uniqueName(),
        role: 'server',
        networks: { provisioning: { vlan: 100 }, trusted: { vlan: 200 }, quarantine: { vlan: 300 } },
      });
      const stored = (await listed(sdk)).find((x) => String(x.id) === p.id);
      expect(Object.keys((stored?.networks as Record<string, unknown> | undefined) ?? {}).sort()).toEqual([
        'provisioning',
        'quarantine',
        'trusted',
      ]);
      await openProfiles(adminPage, p.name);
      const r = row(adminPage, p.name);
      const provisioning = r.getByText('provisioning (VLAN 100)');
      const trusted = r.getByText('trusted (VLAN 200)');
      await expect(provisioning).toBeVisible();
      await expect(trusted).toBeVisible();
      await expect(r.getByText('quarantine (VLAN 300)')).toBeVisible();
      await expect(provisioning.locator('..')).toContainText('enrollment');
      await expect(trusted.locator('..')).toContainText('post-enrollment');
    });

    test('should render a phase key outside the three defaults', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server', networks: { 'lab-dmz': { vlan: 42 } } });
      await openProfiles(adminPage, p.name);
      const r = row(adminPage, p.name);
      await expect(r.getByText('lab-dmz (VLAN 42)')).toBeVisible();
      await expect(r.getByText(/no networks/i)).toHaveCount(0);
    });

    test('should mark the phase a selector names, not the default key', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, {
        name: uniqueName(),
        role: 'server',
        networks: { trusted: { vlan: 200 }, backup: { vlan: 201 } },
        post_enrollment_network: 'backup',
      });
      const stored = (await listed(sdk)).find((x) => String(x.id) === p.id);
      expect(stored?.post_enrollment_network).toBe('backup');
      await openProfiles(adminPage, p.name);
      const r = row(adminPage, p.name);
      const backup = r.getByText('backup (VLAN 201)');
      const trusted = r.getByText('trusted (VLAN 200)');
      await expect(backup).toBeVisible();
      await expect(backup.locator('..')).toContainText('post-enrollment');
      await expect(trusted.locator('..')).not.toContainText('post-enrollment');
    });

    test('should show no networks message when profile has no networks', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      await expect(row(adminPage, p.name).getByText('No networks')).toBeVisible();
    });

    test('should show role badges correctly', async ({ adminPage, sdk }) => {
      const a = await seed(sdk, { name: uniqueName(), role: 'server' });
      const b = await seed(sdk, { name: uniqueName(), role: 'iot' });
      const c = await seed(sdk, { name: uniqueName(), role: 'workstation' });
      await openProfiles(adminPage, c.name);
      await expect(row(adminPage, a.name).getByText('Server', { exact: true })).toBeVisible();
      await expect(row(adminPage, b.name).getByText('IoT', { exact: true })).toBeVisible();
      await expect(row(adminPage, c.name).getByText('Workstation', { exact: true })).toBeVisible();
    });

    // gap: should handle create profile error: the mock injects a 500 on POST; the dialog sends only a name, an optional model and a role from a fixed list the page validates first, so the form cannot send a profile the real server refuses (an unknown role is a 400 from ParseDeviceRole, but the page never sends one)

    test('should handle delete profile error', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      // Another session deletes the profile while the page still lists it.
      const first = await sdk.device.deleteProfile(p.id);
      expect(first.success).toBe(true);
      const again = await sdk.device.deleteProfile(p.id);
      adminPage.once('dialog', (d) => void d.accept());
      await openRowMenu(adminPage, p.name);
      await adminPage.getByRole('menuitem', { name: /delete/i }).click();
      if (again.success) {
        // The server deletes idempotently: the page reports the delete and re-reads.
        await expect(adminPage.getByText('Profile deleted', { exact: true })).toBeVisible();
        await expect(adminPage.getByText(p.name, { exact: true })).toHaveCount(0);
      } else {
        await expect(adminPage.getByText('Error deleting profile', { exact: true })).toBeVisible();
        const message = serverMessage(again.error) || serverMessage({ error: again.error });
        if (message) await expect(adminPage.getByText(message).first()).toBeVisible();
        await expect(adminPage.getByText('Profile deleted', { exact: true })).toHaveCount(0);
      }
    });

    test('should refresh profiles list', async ({ adminPage, sdk }) => {
      const a = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, a.name);
      const b = await seed(sdk, { name: uniqueName(), role: 'iot' });
      await expect(adminPage.getByText(b.name, { exact: true })).toHaveCount(0);
      await adminPage.getByRole('button', { name: /refresh/i }).click();
      await expect(row(adminPage, b.name).getByText('IoT', { exact: true })).toBeVisible();
    });

    test('should clear filters', async ({ adminPage, sdk }) => {
      const a = await seed(sdk, { name: uniqueName(), role: 'server' });
      const b = await seed(sdk, { name: uniqueName(), role: 'iot' });
      await openProfiles(adminPage, b.name);
      const search = adminPage.getByPlaceholder('Search profiles...');
      await search.fill(a.name);
      await expect(adminPage.getByText(b.name, { exact: true })).toHaveCount(0);
      await adminPage.getByRole('button', { name: 'Clear filters' }).click();
      await expect(search).toHaveValue('');
      await expect(adminPage.getByText(a.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByText(b.name, { exact: true })).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Clear filters' })).toHaveCount(0);
    });

    // gap: should show loading state: the mock delays the list answer to hold the spinner; the real server answers at once and the harness cannot hold a request open

    test('should close create dialog on cancel', async ({ adminPage, sdk }) => {
      const p = await seed(sdk, { name: uniqueName(), role: 'server' });
      await openProfiles(adminPage, p.name);
      const name = uniqueName();
      await adminPage.getByRole('button', { name: /create profile/i }).first().click();
      const dialog = adminPage.getByRole('dialog');
      await dialog.getByLabel('Profile Name').fill(name);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
      await expect(dialog).toBeHidden();
      expect((await listed(sdk)).some((x) => x.name === name)).toBe(false);
    });
  });

  test.describe('Access Control', () => {
    // gap: should allow tenant members to view profiles: the harness signs in only its admin (owner of its own tenant) and cannot create a tenant-member session

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/devices/profiles');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });
});
