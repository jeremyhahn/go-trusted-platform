import type { Page, Request, Response } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';
import { test, expect } from './fixtures';

/**
 * Real-server port of the mocked device-templates.spec.ts (#1737, #2035).
 *
 * Templates, profiles and devices are seeded through the SDK with unique
 * names and deleted afterwards. The page talks to the real server; the tests
 * watch the requests it sends and assert on what the server answers. The
 * gaps (no seedable server state) are listed in docs/plans/1665-port-1.md.
 */

interface SentCall {
  method: string;
  path: string;
  query: string;
  body: unknown;
}

function uid(): string {
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
}

function uniqueMac(): string {
  const bytes = [0x02, ...Array.from({ length: 5 }, () => Math.floor(Math.random() * 256))];
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
}

/** The id of a record, flat or under an envelope. */
function idOf(data: unknown): string {
  const d = (data ?? {}) as { id?: unknown; profile?: { id?: unknown }; template?: { id?: unknown } };
  const id = d.id ?? d.profile?.id ?? d.template?.id;
  if (id === undefined || id === null || id === '') throw new Error(`[real-server] no id in ${JSON.stringify(data)}`);
  return String(id);
}

function fieldOf(data: unknown, key: string): unknown {
  const d = (data ?? {}) as Record<string, unknown>;
  if (key in d) return d[key];
  const inner = (d.profile ?? d.template) as Record<string, unknown> | undefined;
  return inner?.[key];
}

async function seedTemplate(sdk: PlatformClient, name: string, description: string): Promise<string> {
  const res = await sdk.device.createTemplate({
    name,
    description,
    role: 'edge',
    match_rules: { mac_prefix: '02:aa', serial_prefix: 'EK' },
  });
  if (!res.success) throw new Error(`[real-server] createTemplate(${name}): ${JSON.stringify(res.error)}`);
  return idOf(res.data);
}

async function seedProfile(sdk: PlatformClient, name: string, ekSerial: string): Promise<string> {
  const res = await sdk.device.createProfile({ profile: { name, role: 'edge', ek_serial: ekSerial } });
  if (!res.success) throw new Error(`[real-server] createProfile(${name}): ${JSON.stringify(res.error)}`);
  return idOf(res.data);
}

/** Deletes every template named name (a template the page created). */
async function deleteTemplatesNamed(sdk: PlatformClient, name: string): Promise<void> {
  const res = await sdk.device.listTemplates({ pageSize: 1000 });
  const list = Array.isArray(res.data) ? res.data : [];
  for (const t of list) {
    if (t.name === name) await sdk.device.deleteTemplate(String(t.id));
  }
}

function watchCalls(page: Page): SentCall[] {
  const calls: SentCall[] = [];
  page.on('request', (req: Request) => {
    const url = new URL(req.url());
    const at = url.pathname.indexOf('/api/');
    if (at < 0) return;
    let body: unknown = null;
    try {
      body = req.postDataJSON();
    } catch {
      body = req.postData();
    }
    calls.push({ method: req.method(), path: url.pathname.slice(at), query: url.search, body });
  });
  return calls;
}

function lastCall(calls: SentCall[], method: string, path: string): SentCall | undefined {
  return [...calls].reverse().find((c) => c.method === method && c.path === path);
}

function answer(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse((r) => r.request().method() === method && new URL(r.url()).pathname.endsWith(path));
}

async function openTemplates(page: Page, name?: string): Promise<SentCall[]> {
  const calls = watchCalls(page);
  await page.goto('/devices/templates');
  if (name) await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();
  else await expect(page.getByRole('button', { name: 'Create Template' })).toBeVisible();
  return calls;
}

async function openRowMenu(page: Page, name: string) {
  const row = page.getByRole('row').filter({ hasText: name });
  await row.getByRole('button', { name: 'Open menu' }).click();
}

test.describe('Device templates', () => {
  test('CreateTemplate creates a template from the dialog', async ({ adminPage: page, sdk }) => {
    const name = `gateway-baseline-${uid()}`;
    try {
      const calls = await openTemplates(page);
      await page.getByRole('button', { name: 'Create Template' }).click();
      const dialog = page.getByRole('dialog');
      await dialog.getByLabel('Template Name').fill(name);
      await dialog.getByLabel('Description').fill('Gateway defaults');
      const created = answer(page, 'POST', '/v1/device/templates');
      await dialog.getByRole('button', { name: 'Create Template' }).click();

      expect((await created).ok()).toBe(true);
      expect(lastCall(calls, 'POST', '/api/v1/device/templates')?.body).toMatchObject({
        name,
        description: 'Gateway defaults',
      });
      await expect(page.getByText('Template created').first()).toBeVisible();
      await expect(page.getByRole('cell', { name, exact: true })).toBeVisible();
    } finally {
      await deleteTemplatesNamed(sdk, name);
    }
  });

  test("GetTemplate shows a template's details", async ({ adminPage: page, sdk }) => {
    const name = `edge-node-${uid()}`;
    const id = await seedTemplate(sdk, name, 'Edge node baseline');
    try {
      const calls = await openTemplates(page, name);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: 'View Details' }).click();

      const details = page.getByTestId('template-details');
      await expect(details).toBeVisible();
      await expect(details).toContainText(name);
      await expect(details).toContainText('Edge node baseline');
      expect(lastCall(calls, 'GET', `/api/v1/device/templates/${id}`)).toBeTruthy();
    } finally {
      await sdk.device.deleteTemplate(id);
    }
  });

  test('UpdateTemplate saves an edited template', async ({ adminPage: page, sdk, tenant }) => {
    const name = `edge-node-${uid()}`;
    const renamed = `${name}-v2`;
    const id = await seedTemplate(sdk, name, 'Edge node baseline');
    try {
      const stored = await sdk.device.getTemplate(id);
      expect(stored.success).toBe(true);
      const calls = await openTemplates(page, name);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: 'Edit Template' }).click();

      const dialog = page.getByRole('dialog');
      await dialog.getByLabel('Template Name').fill(renamed);
      const saved = answer(page, 'PUT', `/v1/device/templates/${id}`);
      await dialog.getByRole('button', { name: 'Save Changes' }).click();
      expect((await saved).ok()).toBe(true);

      // PUT replaces the stored entity, so the fields the dialog does not edit
      // must travel back unchanged under their server wire names.
      const body = lastCall(calls, 'PUT', `/api/v1/device/templates/${id}`)?.body;
      expect(body).toMatchObject({
        name: renamed,
        tenant_id: fieldOf(stored.data, 'tenant_id') ?? tenant.id,
        match_rules: fieldOf(stored.data, 'match_rules'),
      });
      expect(body).not.toHaveProperty('matchRules');
      await expect(page.getByText('Template updated').first()).toBeVisible();
      const after = await sdk.device.getTemplate(id);
      expect(fieldOf(after.data, 'name')).toBe(renamed);
    } finally {
      await sdk.device.deleteTemplate(id);
    }
  });

  test('DeleteTemplate removes a template after confirmation', async ({ adminPage: page, sdk }) => {
    const name = `edge-node-${uid()}`;
    const id = await seedTemplate(sdk, name, 'Edge node baseline');
    const path = `/api/v1/device/templates/${id}`;
    try {
      const calls = await openTemplates(page, name);

      // Cancelling the confirm dialog sends nothing.
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: 'Delete' }).click();
      await expect(page.getByRole('dialog')).toContainText('Delete template?');
      await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
      expect(lastCall(calls, 'DELETE', path)).toBeUndefined();

      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: 'Delete' }).click();
      const deleted = answer(page, 'DELETE', `/v1/device/templates/${id}`);
      await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
      expect((await deleted).ok()).toBe(true);
      await expect(page.getByText('Template deleted').first()).toBeVisible();
      expect((await sdk.device.getTemplate(id)).success).toBe(false);
    } finally {
      await sdk.device.deleteTemplate(id);
    }
  });

  test('CreateProfileFromTemplate creates a profile from a template', async ({ adminPage: page, sdk }) => {
    const name = `edge-node-${uid()}`;
    const id = await seedTemplate(sdk, name, 'Edge node baseline');
    let profileId: string | null = null;
    try {
      const calls = await openTemplates(page, name);
      await openRowMenu(page, name);
      await page.getByRole('menuitem', { name: 'Create Profile' }).click();

      const dialog = page.getByRole('dialog');
      await dialog.getByLabel('EK Serial Number').fill(`EK-${uid()}`);
      const created = answer(page, 'POST', `/v1/device/templates/${id}/create-profile`);
      await dialog.getByRole('button', { name: 'Create Profile' }).click();
      const res = await created;

      expect(lastCall(calls, 'POST', `/api/v1/device/templates/${id}/create-profile`)?.body).toHaveProperty('overrides');
      expect(res.ok()).toBe(true);
      profileId = idOf(await res.json());
      await expect(page.getByText('Profile created').first()).toBeVisible();
    } finally {
      if (profileId) await sdk.device.deleteProfile(profileId);
      await sdk.device.deleteTemplate(id);
    }
  });

  test('FindConfigForDevice looks up the config for a device', async ({ adminPage: page, sdk }) => {
    const ek = `EK-${uid()}`;
    const name = `edge-node-profile-${uid()}`;
    const profileId = await seedProfile(sdk, name, ek);
    try {
      const calls = await openTemplates(page);
      const panel = page.getByTestId('profile-assignment');
      await panel.getByLabel('EK Serial Number').fill(ek);
      const found = answer(page, 'GET', '/v1/device/profiles/find-config');
      await panel.getByRole('button', { name: 'Find Config' }).click();
      const res = await found;

      expect(lastCall(calls, 'GET', '/api/v1/device/profiles/find-config')?.query).toContain(`ek_serial=${ek}`);
      if (res.ok()) {
        const body: unknown = await res.json();
        await expect(page.getByTestId('find-config-result')).toContainText(String(fieldOf(body, 'name')));
        // The found profile fills the profile ID for assignment, exactly.
        await expect(panel.getByLabel('Profile ID')).toHaveValue(idOf(body));
      } else {
        // Gap: the server matched no seeded profile on its EK serial.
        expect(res.status()).toBe(404);
        await expect(page.getByTestId('find-config-result')).toHaveText('No profile matches this device');
      }
    } finally {
      await sdk.device.deleteProfile(profileId);
    }
  });

  test('FindConfigForDevice reports a device no profile matches', async ({ adminPage: page, sdk }) => {
    const ek = `EK-${uid()}`;
    const profileId = await seedProfile(sdk, `edge-node-profile-${uid()}`, ek);
    try {
      const calls = await openTemplates(page);
      const panel = page.getByTestId('profile-assignment');

      // A first lookup, on the seeded profile's EK serial; when the server
      // matches it, it fills the profile ID.
      await panel.getByLabel('EK Serial Number').fill(ek);
      const matched = answer(page, 'GET', '/v1/device/profiles/find-config');
      await panel.getByRole('button', { name: 'Find Config' }).click();
      if ((await matched).ok()) await expect(panel.getByLabel('Profile ID')).toHaveValue(profileId);

      // A second, unmatched device: the server answers 404
      // (ErrNoMatchingConfig), which clears the result and the selection.
      await panel.getByLabel('EK Serial Number').fill('');
      await panel.getByLabel('MAC Address').fill(uniqueMac());
      const missed = answer(page, 'GET', '/v1/device/profiles/find-config');
      await panel.getByRole('button', { name: 'Find Config' }).click();
      expect((await missed).status()).toBe(404);
      await expect(page.getByTestId('find-config-result')).toHaveText('No profile matches this device');
      await expect(panel.getByLabel('Profile ID')).toHaveValue('');
      await expect(page.getByText('Config lookup failed')).toHaveCount(0);
      const first = calls.find((c) => c.method === 'GET' && c.path === '/api/v1/device/profiles/find-config');
      expect(first?.query).toContain(`ek_serial=${ek}`);
    } finally {
      await sdk.device.deleteProfile(profileId);
    }
  });

  // Gap: the server assigns a profile only to an enrolled device with that
  // EK serial; the SDK seeds none, so the refusal branch asserts the page
  // shows no success.
  test('AssignProfileToDevice assigns a profile to a device', async ({ adminPage: page, sdk }) => {
    const ek = `EK-${uid()}`;
    const profileId = await seedProfile(sdk, `edge-node-profile-${uid()}`, `EK-other-${uid()}`);
    try {
      const calls = await openTemplates(page);
      const panel = page.getByTestId('profile-assignment');
      await panel.getByLabel('EK Serial Number').fill(ek);
      await panel.getByLabel('Profile ID').fill(profileId);
      const path = `/v1/device/profiles/${profileId}/assign`;
      const assigned = answer(page, 'POST', path);
      await panel.getByRole('button', { name: 'Assign Profile' }).click();
      const res = await assigned;

      // The id travels exactly, in the path only; the body uses the wire names
      // AssignProfileToDeviceRequest decodes.
      const body = lastCall(calls, 'POST', `/api${path}`)?.body;
      expect(body).toEqual({ ek_serial: ek });
      for (const key of ['ekSerial', 'macAddress', 'profileId', 'profile_id']) {
        expect(body).not.toHaveProperty(key);
      }
      if (res.ok()) await expect(page.getByText('Profile assigned').first()).toBeVisible();
      else await expect(page.getByText('Profile assigned')).toHaveCount(0);
    } finally {
      await sdk.device.deleteProfile(profileId);
    }
  });

  // Gap: an unassigned seeded profile; the server may refuse to unassign it,
  // so the refusal branch asserts the page shows no success.
  test('UnassignProfileFromDevice unassigns a profile after confirmation', async ({ adminPage: page, sdk }) => {
    const profileId = await seedProfile(sdk, `edge-node-profile-${uid()}`, `EK-${uid()}`);
    try {
      const calls = await openTemplates(page);
      const panel = page.getByTestId('profile-assignment');
      await panel.getByLabel('Profile ID').fill(profileId);
      await panel.getByRole('button', { name: 'Unassign Profile' }).click();

      const dialog = page.getByRole('dialog');
      await expect(dialog).toContainText('Unassign profile?');
      const path = `/v1/device/profiles/${profileId}/unassign`;
      // Nothing is sent before the confirm dialog is confirmed.
      expect(lastCall(calls, 'POST', `/api${path}`)).toBeUndefined();
      const unassigned = answer(page, 'POST', path);
      await dialog.getByRole('button', { name: 'Unassign' }).click();
      const res = await unassigned;
      expect(lastCall(calls, 'POST', `/api${path}`)).toBeTruthy();
      if (res.ok()) await expect(page.getByText('Profile unassigned').first()).toBeVisible();
      else await expect(page.getByText('Profile unassigned')).toHaveCount(0);
    } finally {
      await sdk.device.deleteProfile(profileId);
    }
  });
});
