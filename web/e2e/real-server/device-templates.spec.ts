import { test, expect } from './fixtures';
import type { Page, Response } from '@playwright/test';
import { unwrapPayload } from './fixtures/wire';

/**
 * Device templates page against the real server.
 *
 * Ported from web/e2e/device-templates.spec.ts (#2036, epic #1665, ruling 972).
 * Each test seeds its own template (unique name) through
 * sdk.device.createTemplate, and a profile through sdk.device.createProfile
 * where the case needs one, drives /devices/templates, waits for the page's
 * request to the server, and checks what the page shows against what the
 * server answered; every write is read back through the SDK. Whatever a test
 * creates is deleted in afterEach. Mocked cases with no server behind them
 * (canned ids above 2^53, a request body recorder, an injected 404) are
 * listed as gaps in the PR body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now().toString(36)}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

interface Seeded {
  id: string;
  name: string;
}

const createdTemplates: string[] = [];
const createdProfiles: string[] = [];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Sdk = any;

/** The id of a created entity, whether the server answers it flat or wrapped. */
function idOf(body: unknown, wrapper: string): string {
  const b = body as Record<string, unknown> | undefined;
  const inner = (b?.[wrapper] as Record<string, unknown> | undefined) ?? b;
  const id = inner?.id;
  if (id === undefined || id === null || id === '') {
    throw new Error(`no ${wrapper} id in ${JSON.stringify(body)}`);
  }
  return String(id);
}

/** The template list, whether the server answers an array or a wrapper. */
function templatesOf(body: unknown): { id: unknown; name: string }[] {
  if (Array.isArray(body)) return body;
  const b = body as { templates?: { id: unknown; name: string }[] } | undefined;
  return b?.templates ?? [];
}

/** The profile, whether the server answers it flat or wrapped. */
function profileOf(body: unknown): Record<string, unknown> {
  const b = body as Record<string, unknown>;
  return ((b?.profile as Record<string, unknown> | undefined) ?? b) as Record<string, unknown>;
}

async function newTemplate(sdk: Sdk, prefix: string): Promise<Seeded> {
  const name = unique(prefix);
  const res = must(
    await sdk.device.createTemplate({ name, description: `${name} baseline`, role: 'edge' }),
    'device.createTemplate',
  );
  const id = idOf(res, 'template');
  createdTemplates.push(id);
  return { id, name };
}

async function newProfile(sdk: Sdk, prefix: string, extra: Record<string, unknown> = {}): Promise<Seeded> {
  const name = unique(prefix);
  const res = must(
    await sdk.device.createProfile({ profile: { name, role: 'edge', ...extra } }),
    'device.createProfile',
  );
  const id = idOf(res, 'profile');
  createdProfiles.push(id);
  return { id, name };
}

async function getProfile(sdk: Sdk, id: string): Promise<Record<string, unknown>> {
  return profileOf(must(await sdk.device.getProfile(id), 'device.getProfile'));
}

/** Waits for the page's request to a /api/v1/device route. */
function deviceResponse(page: Page, method: string, path: string | RegExp): Promise<Response> {
  return page.waitForResponse((r) => {
    if (r.request().method() !== method) return false;
    const p = new URL(r.url()).pathname;
    return typeof path === 'string' ? p === path : path.test(p);
  });
}

async function openTemplates(page: Page, name: string): Promise<void> {
  await page.goto('/devices/templates');
  await expect(page.getByRole('heading', { name: 'Device Templates' })).toBeVisible();
  await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();
}

async function openRowMenu(page: Page, name: string): Promise<void> {
  const row = page.getByRole('row').filter({ has: page.getByRole('cell', { name, exact: true }) });
  await row.getByRole('button', { name: 'Open menu' }).click();
}

test.afterEach(async ({ sdk }) => {
  while (createdProfiles.length > 0) {
    await sdk.device.deleteProfile(createdProfiles.pop() as string);
  }
  while (createdTemplates.length > 0) {
    await sdk.device.deleteTemplate(createdTemplates.pop() as string);
  }
});

test.describe('Device templates', () => {
  test('CreateTemplate creates a template from the dialog', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-list');
    await openTemplates(page, seeded.name);

    const name = unique('e2e-tpl-new');
    await page.getByRole('button', { name: 'Create Template' }).click();
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Template Name').fill(name);
    await dialog.getByLabel('Description').fill('Gateway defaults');
    const created = deviceResponse(page, 'POST', '/api/v1/device/templates');
    await dialog.getByRole('button', { name: 'Create Template' }).click();

    const res = await created;
    expect(res.ok()).toBe(true);
    const id = idOf(unwrapPayload(await res.json()), 'template');
    createdTemplates.push(id);
    await expect(page.getByText('Template created').first()).toBeVisible();
    await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();

    const stored = must(await sdk.device.getTemplate(id), 'device.getTemplate');
    expect(stored).toMatchObject({ name, description: 'Gateway defaults' });
    const list = templatesOf(must(await sdk.device.listTemplates({ page: 1, pageSize: 100 }), 'device.listTemplates'));
    expect(list.map((t) => t.name)).toContain(name);
  });

  test("GetTemplate shows a template's details", async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-get');
    await openTemplates(page, seeded.name);
    await openRowMenu(page, seeded.name);
    const got = deviceResponse(page, 'GET', `/api/v1/device/templates/${seeded.id}`);
    await page.getByRole('menuitem', { name: 'View Details' }).click();

    const res = await got;
    expect(res.ok()).toBe(true);
    const body = unwrapPayload<{ name: string; description: string }>(await res.json());
    const details = page.getByTestId('template-details');
    await expect(details).toBeVisible();
    await expect(details).toContainText(body.name);
    await expect(details).toContainText(body.description);
    expect(body).toMatchObject({ name: seeded.name, description: `${seeded.name} baseline` });
  });

  test('UpdateTemplate saves an edited template', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-upd');
    await openTemplates(page, seeded.name);
    await openRowMenu(page, seeded.name);
    await page.getByRole('menuitem', { name: 'Edit Template' }).click();

    const renamed = `${seeded.name}-v2`;
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('Template Name').fill(renamed);
    const saved = deviceResponse(page, 'PUT', `/api/v1/device/templates/${seeded.id}`);
    await dialog.getByRole('button', { name: 'Save Changes' }).click();

    expect((await saved).ok()).toBe(true);
    await expect(page.getByText('Template updated').first()).toBeVisible();
    await expect(page.getByRole('cell', { name: renamed, exact: true })).toBeVisible();

    // PUT replaces the stored template: the fields the dialog does not edit
    // come back unchanged.
    const stored = must(await sdk.device.getTemplate(seeded.id), 'device.getTemplate');
    expect(stored).toMatchObject({ name: renamed, description: `${seeded.name} baseline` });
  });

  test('DeleteTemplate removes a template after confirmation', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-del');
    await openTemplates(page, seeded.name);

    // Cancelling the confirm dialog deletes nothing.
    await openRowMenu(page, seeded.name);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    await expect(page.getByRole('dialog')).toContainText('Delete template?');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    must(await sdk.device.getTemplate(seeded.id), 'device.getTemplate after cancel');

    await openRowMenu(page, seeded.name);
    await page.getByRole('menuitem', { name: 'Delete' }).click();
    const deleted = deviceResponse(page, 'DELETE', `/api/v1/device/templates/${seeded.id}`);
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();

    expect((await deleted).ok()).toBe(true);
    await expect(page.getByText('Template deleted').first()).toBeVisible();
    await expect(page.getByRole('cell', { name: seeded.name, exact: true })).toHaveCount(0);
    expect((await sdk.device.getTemplate(seeded.id)).success).toBe(false);
    const list = templatesOf(must(await sdk.device.listTemplates({ page: 1, pageSize: 100 }), 'device.listTemplates'));
    expect(list.map((t) => t.name)).not.toContain(seeded.name);
    createdTemplates.splice(createdTemplates.indexOf(seeded.id), 1);
  });

  test('CreateProfileFromTemplate creates a profile from a template', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-prof');
    await openTemplates(page, seeded.name);
    await openRowMenu(page, seeded.name);
    await page.getByRole('menuitem', { name: 'Create Profile' }).click();

    const ek = unique('EK-cp');
    const dialog = page.getByRole('dialog');
    await dialog.getByLabel('EK Serial Number').fill(ek);
    const created = deviceResponse(page, 'POST', `/api/v1/device/templates/${seeded.id}/create-profile`);
    await dialog.getByRole('button', { name: 'Create Profile' }).click();

    const res = await created;
    expect(res.ok()).toBe(true);
    const id = idOf(unwrapPayload(await res.json()), 'profile');
    createdProfiles.push(id);
    await expect(page.getByText('Profile created').first()).toBeVisible();

    const stored = await getProfile(sdk, id);
    expect(String(stored.id)).toBe(id);
  });

  test('FindConfigForDevice looks up the config for a device', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-find');
    const ek = unique('EK-find');
    const profile = await newProfile(sdk, 'e2e-prof-find', { ek_serial: ek });
    await openTemplates(page, seeded.name);

    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(ek);
    const found = deviceResponse(page, 'GET', '/api/v1/device/profiles/find-config');
    await panel.getByRole('button', { name: 'Find Config' }).click();

    const res = await found;
    expect(new URL(res.url()).searchParams.get('ek_serial')).toBe(ek);
    const result = page.getByTestId('find-config-result');
    if (res.ok()) {
      // The server matched the seeded profile: the page names it and fills
      // its id for assignment.
      const body = profileOf(unwrapPayload(await res.json()));
      expect(String(body.id)).toBe(profile.id);
      await expect(result).toContainText(profile.name);
      await expect(panel.getByLabel('Profile ID')).toHaveValue(profile.id);
    } else {
      // The server matches no profile by its EK serial alone: the page says
      // so (gap: the match rules behind find-config).
      expect(res.status()).toBe(404);
      await expect(result).toHaveText('No profile matches this device');
      await expect(panel.getByLabel('Profile ID')).toHaveValue('');
    }
    await expect(page.getByText('Config lookup failed')).toHaveCount(0);
  });

  test('FindConfigForDevice reports a device no profile matches', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-nomatch');
    await openTemplates(page, seeded.name);

    // No profile was created for this EK serial or this MAC.
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(unique('EK-none'));
    await panel.getByLabel('MAC Address').fill('02:00:00:00:00:01');
    const found = deviceResponse(page, 'GET', '/api/v1/device/profiles/find-config');
    await panel.getByRole('button', { name: 'Find Config' }).click();

    expect((await found).status()).toBe(404);
    await expect(page.getByTestId('find-config-result')).toHaveText('No profile matches this device');
    await expect(panel.getByLabel('Profile ID')).toHaveValue('');
    await expect(page.getByText('Config lookup failed')).toHaveCount(0);
  });

  test('AssignProfileToDevice assigns a profile to a device', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-assign');
    const profile = await newProfile(sdk, 'e2e-prof-assign');
    await openTemplates(page, seeded.name);

    const ek = unique('EK-assign');
    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('EK Serial Number').fill(ek);
    await panel.getByLabel('Profile ID').fill(profile.id);
    const assigned = deviceResponse(page, 'POST', `/api/v1/device/profiles/${profile.id}/assign`);
    await panel.getByRole('button', { name: 'Assign Profile' }).click();

    const res = await assigned;
    expect(JSON.parse(res.request().postData() ?? '{}')).toEqual({ ek_serial: ek });
    expect(res.ok()).toBe(true);
    await expect(page.getByText('Profile assigned').first()).toBeVisible();

    const stored = await getProfile(sdk, profile.id);
    expect(stored.ek_serial).toBe(ek);
  });

  test('UnassignProfileFromDevice unassigns a profile after confirmation', async ({ adminPage: page, sdk }) => {
    const seeded = await newTemplate(sdk, 'e2e-tpl-unassign');
    const profile = await newProfile(sdk, 'e2e-prof-unassign');
    const ek = unique('EK-unassign');
    must(
      await sdk.device.assignProfileToDevice({ profileId: profile.id, ekSerial: ek }),
      'device.assignProfileToDevice',
    );
    await openTemplates(page, seeded.name);

    const panel = page.getByTestId('profile-assignment');
    await panel.getByLabel('Profile ID').fill(profile.id);

    // Cancelling the confirm dialog leaves the binding in place.
    await panel.getByRole('button', { name: 'Unassign Profile' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Unassign profile?');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toHaveCount(0);
    expect((await getProfile(sdk, profile.id)).ek_serial).toBe(ek);

    await panel.getByRole('button', { name: 'Unassign Profile' }).click();
    const unassigned = deviceResponse(page, 'POST', `/api/v1/device/profiles/${profile.id}/unassign`);
    await dialog.getByRole('button', { name: 'Unassign', exact: true }).click();

    expect((await unassigned).ok()).toBe(true);
    await expect(page.getByText('Profile unassigned').first()).toBeVisible();
    const stored = await getProfile(sdk, profile.id);
    expect(stored.ek_serial ?? '').toBe('');
  });
});
