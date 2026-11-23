import type { Page, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * The Device vTPM cases of the mocked web/e2e/devices.spec.ts, against the
 * real-server harness (#2035, epic #1665).
 *
 * Bundles are seeded through sdk.vtpm.createBundle with a unique hostname
 * (the page shows a bundle by its manifest hostname, its id as the VM ID) and
 * deleted after each case. The page lists with GET /api/v1/vtpm/bundles; if
 * the server refuses the seed or the list (the test config has no vtpm
 * section, so the service may answer 503), the case asserts what the page
 * shows for that refusal instead of the seeded row.
 *
 * The page maps every bundle to state `active` and an empty PCR profile
 * (devices/vtpm/page.tsx :63-78), so the Sealed, Migrating and Suspended
 * badges and a named PCR profile cannot come from the server: the cases
 * assert what the page really renders for a real bundle.
 */

interface Answer {
  ok: boolean;
  status: number;
  body: unknown;
}

interface Seed {
  name: string;
  id: string;
}

/** The message of a platform error envelope, in either of its two shapes. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

/** The id of a bundle answer: the bundle itself or a {data} envelope around it. */
function bundleId(data: unknown): string {
  const d = (data ?? {}) as { id?: string; data?: { id?: string } };
  return d.data?.id ?? d.id ?? '';
}

function isList(r: Response): boolean {
  return r.request().method() === 'GET' && /\/api\/v1\/vtpm\/bundles\/?$/.test(new URL(r.url()).pathname);
}

function isCreate(r: Response): boolean {
  return r.request().method() === 'POST' && /\/api\/v1\/vtpm\/bundles\/?$/.test(new URL(r.url()).pathname);
}

function isDelete(r: Response): boolean {
  return r.request().method() === 'DELETE' && /\/api\/v1\/vtpm\/bundles\/[^/]+$/.test(new URL(r.url()).pathname);
}

async function answerOf(res: Response): Promise<Answer> {
  return { ok: res.ok(), status: res.status(), body: await res.json().catch(() => null) };
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Bundles seeded by the running case, deleted in afterEach. */
const seeded: { sdk: PlatformClient; id: string }[] = [];
/** Hostnames the console created in the running case, deleted in afterEach. */
const created: { sdk: PlatformClient; name: string }[] = [];

async function cleanup(): Promise<void> {
  for (const { sdk, id } of seeded.splice(0)) {
    await sdk.vtpm.deleteBundle(id).catch(() => undefined);
  }
  for (const { sdk, name } of created.splice(0)) {
    const res = await sdk.vtpm.listBundles({ options: { limit: 100 } }).catch(() => undefined);
    const data = (res?.data ?? {}) as { bundles?: { id?: string; manifest?: { hostname?: string } }[] };
    for (const b of data.bundles ?? []) {
      if (b.id && b.manifest?.hostname === name) await sdk.vtpm.deleteBundle(b.id).catch(() => undefined);
    }
  }
}

/** Seeds count bundles; refusal is the server's message when it refused one. */
async function seedBundles(sdk: PlatformClient, count: number): Promise<{ seeds: Seed[]; refusal: string | null }> {
  const stamp = Date.now();
  const seeds: Seed[] = [];
  for (let n = 1; n <= count; n++) {
    const name = `e2e-vtpm-${stamp}-${n}`;
    const res = await sdk.vtpm.createBundle({ options: { hostname: name } });
    const id = bundleId(res.data);
    if (!res.success || !id) {
      const err = res.error as { message?: string } | undefined;
      return { seeds, refusal: err?.message || JSON.stringify(res.error ?? { status: 'no bundle id' }) };
    }
    seeded.push({ sdk, id });
    seeds.push({ name, id });
  }
  return { seeds, refusal: null };
}

/** Opens the vTPM list and returns the server's answer to its list request. */
async function openList(page: Page): Promise<Answer> {
  const res = page.waitForResponse(isList);
  await page.goto('/devices/vtpm');
  await expect(page.getByRole('heading', { name: 'Virtual TPM (vTPM)' })).toBeVisible();
  const answer = await answerOf(await res);
  await expect(page.getByText('Loading vTPM instances...')).toBeHidden();
  return answer;
}

/** What the page shows for a refused list: the Error toast over an empty table. */
async function expectListRefused(page: Page, list: Answer): Promise<void> {
  expect(list.ok).toBe(false);
  await expect(page.getByText('Error', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('No vTPM instances found')).toBeVisible();
}

/**
 * Seeds count bundles and opens the list. Returns the seeds when the server
 * took them and lists them; otherwise asserts what the page shows for the
 * refusal and returns null.
 */
async function seedAndOpen(page: Page, sdk: PlatformClient, count: number): Promise<Seed[] | null> {
  const { seeds, refusal } = await seedBundles(sdk, count);
  const list = await openList(page);
  if (refusal !== null) {
    expect(refusal).not.toBe('');
    if (!list.ok) {
      await expectListRefused(page, list);
    } else {
      await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible();
    }
    return null;
  }
  if (!list.ok) {
    await expectListRefused(page, list);
    return null;
  }
  for (const s of seeds) await expect(rowOf(page, s.name)).toBeVisible();
  return seeds;
}

function rowOf(page: Page, name: string) {
  return page.getByRole('row').filter({ hasText: name });
}

async function openMenu(page: Page, name: string): Promise<void> {
  await rowOf(page, name).getByRole('button', { name: 'Open menu' }).click();
  await expect(page.getByRole('menuitem', { name: 'View Details' })).toBeVisible();
}

async function openCreate(page: Page): Promise<void> {
  await page.getByRole('button', { name: /create vtpm/i }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByText('Create New vTPM Instance')).toBeVisible();
}

function submitButton(page: Page) {
  return page.getByRole('dialog').getByRole('button', { name: 'Create vTPM' });
}

test.describe('Device vTPM, real server', () => {
  test.afterEach(async () => {
    await cleanup();
  });

  test.describe('vTPM List', () => {
    test('should display vTPM page header and description', async ({ adminPage }) => {
      const list = await openList(adminPage);
      await expect(adminPage.getByText('Manage virtual TPM instances for VMs and containers')).toBeVisible();
      await expect(adminPage.getByRole('button', { name: /create vtpm/i })).toBeVisible();
      if (!list.ok) await expectListRefused(adminPage, list);
    });

    test('should display vTPM table with columns', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      for (const h of ['Name', 'VM/Container', 'State', 'PCR Profile', 'Created', 'Actions']) {
        await expect(adminPage.getByRole('columnheader', { name: h })).toBeVisible();
      }
      if (!seeds) return;
      const row = rowOf(adminPage, seeds[0].name);
      // Name and VM name are the manifest hostname; the VM ID is the bundle id.
      await expect(row.getByRole('cell').nth(0)).toHaveText(seeds[0].name);
      await expect(row.getByRole('cell').nth(1)).toContainText(seeds[0].name);
      await expect(row.getByRole('cell').nth(1)).toContainText(seeds[0].id);
    });

    test('should display vTPM state badges correctly', async ({ adminPage, sdk }) => {
      // The page maps every bundle to `active`: Sealed, Migrating and
      // Suspended cannot come from the server (page.tsx :68).
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await expect(rowOf(adminPage, seeds[0].name).getByRole('cell').nth(2)).toHaveText('Active');
    });

    test('should show empty state when no vTPM instances', async ({ adminPage }) => {
      // Shared server state: a search no bundle matches is the empty list.
      const list = await openList(adminPage);
      if (!list.ok) {
        await expectListRefused(adminPage, list);
        return;
      }
      await adminPage.getByPlaceholder('Search vTPM instances...').fill(`e2e-vtpm-none-${Date.now()}`);
      await expect(adminPage.getByText('No vTPM instances found')).toBeVisible();
    });

    // gap: should show loading state: the mock delayed the list answer; the real server answers before a spinner can be asserted.

    test('should filter vTPM instances by search query', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 2);
      if (!seeds) return;
      await adminPage.getByPlaceholder('Search vTPM instances...').fill(seeds[0].name);
      await expect(rowOf(adminPage, seeds[0].name)).toBeVisible();
      await expect(rowOf(adminPage, seeds[1].name)).toHaveCount(0);
    });

    test('should filter vTPM instances by VM ID', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 2);
      if (!seeds) return;
      await adminPage.getByPlaceholder('Filter by VM ID...').fill(seeds[1].id);
      await expect(rowOf(adminPage, seeds[1].name)).toBeVisible();
      await expect(rowOf(adminPage, seeds[0].name)).toHaveCount(0);
    });

    test('should filter vTPM instances by state', async ({ adminPage, sdk }) => {
      // The page re-reads the list on a state change but neither sends the
      // state nor filters by it, and every bundle is `active`: a Sealed
      // filter still shows the seeded bundle (gap for the route audit).
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      const reread = adminPage.waitForResponse(isList);
      await adminPage.getByRole('combobox').click();
      await adminPage.getByRole('option', { name: 'Sealed' }).click();
      const list = await answerOf(await reread);
      expect(new URL((await reread).url()).searchParams.has('state')).toBe(false);
      expect(list.ok).toBe(true);
      await expect(rowOf(adminPage, seeds[0].name).getByRole('cell').nth(2)).toHaveText('Active');
      await expect(adminPage.getByRole('button', { name: 'Clear filters' })).toBeVisible();
    });

    test('should clear filters', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 2);
      if (!seeds) return;
      const search = adminPage.getByPlaceholder('Search vTPM instances...');
      await search.fill(seeds[0].name);
      await expect(rowOf(adminPage, seeds[1].name)).toHaveCount(0);
      await adminPage.getByRole('button', { name: 'Clear filters' }).click();
      await expect(search).toHaveValue('');
      await expect(adminPage.getByRole('button', { name: 'Clear filters' })).toBeHidden();
      for (const s of seeds) await expect(rowOf(adminPage, s.name)).toBeVisible();
    });
  });

  test.describe('Create vTPM', () => {
    test('should open create vTPM dialog', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await expect(adminPage.getByText('Create a virtual TPM for a VM or container')).toBeVisible();
    });

    test('should display all form fields in create dialog', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      for (const label of ['vTPM Name', 'VM/Container ID', 'VM/Container Name', 'PCR Profile', 'Description (Optional)']) {
        await expect(adminPage.getByLabel(label)).toBeVisible();
      }
      await expect(submitButton(adminPage)).toBeEnabled();
      await expect(adminPage.getByRole('button', { name: 'Cancel' })).toBeVisible();
    });

    test('should create a new vTPM instance', async ({ adminPage, sdk }) => {
      const name = `e2e-vtpm-${Date.now()}-1`;
      await openList(adminPage);
      await openCreate(adminPage);
      await adminPage.getByLabel('vTPM Name').fill(name);
      await adminPage.getByLabel('VM/Container ID').fill('vm-e2e-1');
      await adminPage.getByLabel('VM/Container Name').fill(name);
      created.push({ sdk, name });
      const answer = adminPage.waitForResponse(isCreate);
      await submitButton(adminPage).click();
      const res = await answer;
      // The console sends the VM name as the bundle hostname.
      expect((res.request().postDataJSON() as { hostname?: string }).hostname).toBe(name);
      const created1 = await answerOf(res);
      if (created1.ok) {
        await expect(adminPage.getByText('vTPM instance created successfully')).toBeVisible();
        await expect(adminPage.getByRole('dialog')).toBeHidden();
        await expect(rowOf(adminPage, name)).toBeVisible();
      } else {
        expect(serverMessage(created1.body)).not.toBe('');
        await expect(adminPage.getByText('Error', { exact: true }).first()).toBeVisible();
        await expect(adminPage.getByText('vTPM instance created successfully')).toBeHidden();
        await expect(adminPage.getByRole('dialog')).toBeVisible();
      }
    });

    test('should validate vTPM name is required', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await submitButton(adminPage).click();
      await expect(adminPage.getByText('Name is required')).toBeVisible();
      await expect(adminPage.getByRole('dialog')).toBeVisible();
    });

    test('should validate VM ID is required', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await adminPage.getByLabel('vTPM Name').fill('e2e-vtpm-validate');
      await submitButton(adminPage).click();
      await expect(adminPage.getByText('VM ID is required')).toBeVisible();
    });

    test('should validate VM name is required', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await adminPage.getByLabel('vTPM Name').fill('e2e-vtpm-validate');
      await adminPage.getByLabel('VM/Container ID').fill('vm-e2e-1');
      await submitButton(adminPage).click();
      await expect(adminPage.getByText('VM name is required')).toBeVisible();
    });

    test('should close create dialog on cancel', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await adminPage.getByRole('button', { name: 'Cancel' }).click();
      await expect(adminPage.getByRole('dialog')).toBeHidden();
    });

    test('should close create dialog with Escape key', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await adminPage.keyboard.press('Escape');
      await expect(adminPage.getByRole('dialog')).toBeHidden();
    });
  });

  test.describe('vTPM Actions', () => {
    test('should open actions menu for vTPM', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await openMenu(adminPage, seeds[0].name);
      for (const item of ['View Details', 'Seal Data', 'Suspend', 'Migrate', 'Delete']) {
        await expect(adminPage.getByRole('menuitem', { name: item })).toBeVisible();
      }
      await expect(adminPage.getByRole('menuitem', { name: 'Resume' })).toHaveCount(0);
    });

    test('should navigate to vTPM details from actions menu', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await openMenu(adminPage, seeds[0].name);
      await adminPage.getByRole('menuitem', { name: 'View Details' }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/vtpm/${escapeRe(seeds[0].id)}/?$`));
    });

    test('should navigate to seal data action', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await openMenu(adminPage, seeds[0].name);
      await adminPage.getByRole('menuitem', { name: 'Seal Data' }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/vtpm/${escapeRe(seeds[0].id)}/?\\?action=seal$`));
    });

    test('should show suspend info toast for active vTPM', async ({ adminPage, sdk }) => {
      // Suspend sends nothing to the server: the page answers it itself.
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await openMenu(adminPage, seeds[0].name);
      await adminPage.getByRole('menuitem', { name: 'Suspend' }).click();
      await expect(adminPage.getByText('Suspend operation not yet implemented in SDK')).toBeVisible();
      await expect(rowOf(adminPage, seeds[0].name).getByRole('cell').nth(2)).toHaveText('Active');
    });

    test('should navigate to migrate action', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await openMenu(adminPage, seeds[0].name);
      await adminPage.getByRole('menuitem', { name: 'Migrate' }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/vtpm/${escapeRe(seeds[0].id)}/?\\?action=migrate$`));
    });

    test('should delete vTPM with confirmation', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      let prompt = '';
      adminPage.once('dialog', (d) => {
        prompt = d.message();
        void d.accept();
      });
      await openMenu(adminPage, seeds[0].name);
      const answer = adminPage.waitForResponse(isDelete);
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      const res = await answerOf(await answer);
      expect(prompt).toContain(`Are you sure you want to delete vTPM ${seeds[0].name}?`);
      if (res.ok) {
        await expect(adminPage.getByText('vTPM deleted successfully')).toBeVisible();
        await expect(rowOf(adminPage, seeds[0].name)).toHaveCount(0);
        expect((await sdk.vtpm.getBundle(seeds[0].id)).success).toBe(false);
      } else {
        expect(serverMessage(res.body)).not.toBe('');
        await expect(adminPage.getByText('Error', { exact: true }).first()).toBeVisible();
        await expect(adminPage.getByText('vTPM deleted successfully')).toBeHidden();
      }
    });

    test('should cancel delete when dialog is dismissed', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      let deletes = 0;
      adminPage.on('response', (r) => {
        if (isDelete(r)) deletes++;
      });
      adminPage.once('dialog', (d) => void d.dismiss());
      await openMenu(adminPage, seeds[0].name);
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      await expect(rowOf(adminPage, seeds[0].name)).toBeVisible();
      expect(deletes).toBe(0);
      expect((await sdk.vtpm.getBundle(seeds[0].id)).success).toBe(true);
    });
  });

  test.describe('Error States', () => {
    // gap: should handle fetch vTPM error: the mock injected a 500 on the list; the real server lists, or refuses for want of a vtpm service, which the vTPM List cases assert through expectListRefused.
    // gap: should handle create vTPM error: the mock injected a 500 on create; the form sends only the hostname of a valid VM name, which the server has no reason to refuse (a refusal is asserted by "should create a new vTPM instance").

    test('should handle delete vTPM error', async ({ adminPage, sdk }) => {
      // The bundle is deleted behind the page's back: the console's delete
      // then reaches a bundle the server no longer has.
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      expect((await sdk.vtpm.deleteBundle(seeds[0].id)).success).toBe(true);
      adminPage.once('dialog', (d) => void d.accept());
      await openMenu(adminPage, seeds[0].name);
      const answer = adminPage.waitForResponse(isDelete);
      await adminPage.getByRole('menuitem', { name: 'Delete' }).click();
      const res = await answerOf(await answer);
      expect(res.ok).toBe(false);
      expect(serverMessage(res.body)).not.toBe('');
      await expect(adminPage.getByText('Error', { exact: true }).first()).toBeVisible();
      await expect(adminPage.getByText('vTPM deleted successfully')).toBeHidden();
    });
  });

  test.describe('Access Control', () => {
    // gap: should allow tenant members to view vTPM instances: the harness signs in only its tenant admin; it cannot create a tenant-member session.

    test('should redirect unauthenticated users to login', async ({ page }) => {
      await page.goto('/devices/vtpm');
      await expect(page).toHaveURL(/\/auth\/webauthn/);
    });
  });

  test.describe('PCR Profile Display', () => {
    test('should display PCR profile badge for vTPM', async ({ adminPage, sdk }) => {
      // The page sets an empty PCR profile for every bundle (page.tsx :77):
      // the badge renders with no text; a named profile cannot come from the
      // server (gap for the route audit).
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      await expect(rowOf(adminPage, seeds[0].name).getByRole('cell').nth(3)).toHaveText('');
    });
  });

  test.describe('Date Formatting', () => {
    test('should display formatted creation date', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 1);
      if (!seeds) return;
      const cell = rowOf(adminPage, seeds[0].name).getByRole('cell').nth(4);
      // en-US short month, day, year, time: "Nov 23, 2026, 10:04 AM".
      await expect(cell).toHaveText(/^[A-Z][a-z]{2} \d{1,2}, \d{4}, \d{2}:\d{2}\s?[AP]M$/);
      await expect(cell).toContainText(String(new Date().getFullYear()));
    });
  });

  test.describe('Multiple vTPM Instances', () => {
    test('should display multiple vTPM instances correctly', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 3);
      if (!seeds) return;
      for (const s of seeds) {
        const row = rowOf(adminPage, s.name);
        await expect(row).toHaveCount(1);
        await expect(row.getByRole('cell').nth(1)).toContainText(s.id);
        await expect(row.getByRole('cell').nth(2)).toHaveText('Active');
      }
    });

    test('should handle actions on specific vTPM in list', async ({ adminPage, sdk }) => {
      const seeds = await seedAndOpen(adminPage, sdk, 2);
      if (!seeds) return;
      await openMenu(adminPage, seeds[1].name);
      await adminPage.getByRole('menuitem', { name: 'View Details' }).click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/vtpm/${escapeRe(seeds[1].id)}/?$`));
    });
  });

  test.describe('Form Fields', () => {
    test('should fill PCR profile field', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      const field = adminPage.getByLabel('PCR Profile');
      await expect(field).toHaveAttribute('placeholder', 'default');
      await field.fill('secure-boot');
      await expect(field).toHaveValue('secure-boot');
    });

    test('should fill description field', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      const field = adminPage.getByLabel('Description (Optional)');
      await field.fill('e2e vTPM description');
      await expect(field).toHaveValue('e2e vTPM description');
    });

    test('should show form descriptions for each field', async ({ adminPage }) => {
      await openList(adminPage);
      await openCreate(adminPage);
      await expect(adminPage.getByText(/a unique name to identify/i)).toBeVisible();
      await expect(adminPage.getByText(/virtual machine or container identifier/i)).toBeVisible();
      await expect(adminPage.getByText(/display name of the vm\/container/i)).toBeVisible();
      await expect(adminPage.getByText(/pcr configuration profile/i)).toBeVisible();
    });
  });
});
