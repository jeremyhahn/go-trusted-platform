import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The device template pages against the real platformd (#2049, epic #1665).
 * No page.route mocks: each assertion compares the page with what the server
 * answered, through the page itself or the SDK, not with a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const CREATE_OP = 'POST /api/v1/device/templates';
const UPDATE_OP = 'PUT /api/v1/device/templates/{id:[0-9]+}';
const DELETE_OP = 'DELETE /api/v1/device/templates/{id:[0-9]+}';
const PROFILE_OP = 'POST /api/v1/device/templates/{id:[0-9]+}/create-profile';

interface Capability {
  op: string;
  enabled: boolean;
  reason?: string;
}

interface ListedTemplate {
  id: string;
  name: string;
}

/** Waits for the page's own GET on exactly this path. */
function apiResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && new URL(r.url()).pathname === path,
  );
}

/** Waits for the page's own request with this method on this path (exact, or a pattern). */
function apiWrite(page: Page, method: string, path: string | RegExp): Promise<Response> {
  return page.waitForResponse((r) => {
    if (r.request().method() !== method) return false;
    const pathname = new URL(r.url()).pathname;
    return typeof path === 'string' ? pathname === path : path.test(pathname);
  });
}

/** The id of a created object, bare or wrapped in { template } / { profile }. */
function createdId(payload: unknown): string {
  const p = payload as { id?: unknown; template?: { id?: unknown }; profile?: { id?: unknown } };
  const id = p?.id ?? p?.template?.id ?? p?.profile?.id;
  if (id === undefined || id === null || id === '') {
    throw new Error(`no id in ${JSON.stringify(payload)}`);
  }
  return String(id);
}

/** A profile answer, bare or wrapped in { profile }. */
function profileOf(data: unknown): { id: string; mac_address?: string } | undefined {
  const wrapped = (data as { profile?: { id: string; mac_address?: string } } | undefined)?.profile;
  return wrapped ?? (data as { id: string; mac_address?: string } | undefined);
}

/** A locally administered MAC (02:00:00 prefix) unique to this run. */
function uniqueMac(): string {
  const n = Date.now();
  const octet = (shift: number) => ((n >> shift) & 0xff).toString(16).padStart(2, '0');
  return `02:00:00:${octet(16)}:${octet(8)}:${octet(0)}`;
}

/** The templates a list answer carries, bare or wrapped in { templates }. */
function templatesOf(payload: unknown): ListedTemplate[] {
  if (Array.isArray(payload)) return payload as ListedTemplate[];
  return ((payload as { templates?: ListedTemplate[] } | undefined)?.templates ?? []);
}

/** Asserts a control carries the server's answer for op. */
async function expectGate(control: Locator, op: string, cap: Capability | undefined) {
  const enabled = cap?.enabled === true;
  await expect(control).toHaveAttribute('data-capability-op', op);
  await expect(control).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
  if (!enabled) {
    await expect(control).toBeDisabled();
    await expect(control).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
  }
}

test.describe('Device templates page', () => {
  test('the templates page lists what the server answers', async ({ adminPage, sdk }) => {
    const listRes = apiResponse(adminPage, '/api/v1/device/templates');
    await adminPage.goto('/devices/templates');
    const list = await listRes;

    if (list.ok()) {
      const listed = templatesOf(unwrapPayload<unknown>(await list.json()));
      const rows = adminPage.getByRole('table').last().locator('tbody tr');
      if (listed.length === 0) {
        await expect(rows).toHaveCount(1);
        await expect(rows.first()).toContainText('No device templates found');
      } else {
        await expect(rows).toHaveCount(listed.length);
        for (const template of listed) {
          await expect(rows.filter({ hasText: template.name }).first()).toBeVisible();
        }
      }
      const viaSdk = await sdk.device.listTemplates();
      expect(viaSdk.success, JSON.stringify(viaSdk.error)).toBeTruthy();
    } else {
      // A refused read: the page's error state.
      await expect(adminPage.getByText('Error Loading Templates')).toBeVisible();
    }
  });

  test('the template write controls are gated on the server\'s capabilities', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c as Capability]),
    );

    await adminPage.goto('/devices/templates');
    await expectGate(
      adminPage.getByRole('button', { name: 'Create Template', exact: true }),
      CREATE_OP,
      listed.get(CREATE_OP),
    );

    // A template to open: one the server lists, or one seeded when it offers the create.
    const existing = await sdk.device.listTemplates();
    let template = existing.success ? templatesOf(existing.data)[0] : undefined;
    let seeded: string | undefined;
    if (!template && listed.get(CREATE_OP)?.enabled) {
      const created = await sdk.device.createTemplate({
        name: `e2e-template-gate-${Date.now()}`,
        role: 'worker',
      });
      expect(created.success, JSON.stringify(created.error)).toBeTruthy();
      template = created.data as ListedTemplate;
      seeded = template.id;
    }
    if (!template) {
      // Nothing to open and nothing may be created: the create stays gated off.
      expect(listed.get(CREATE_OP)?.enabled === true).toBeFalsy();
      return;
    }

    await adminPage.goto(`/devices/templates/${template.id}`);
    await expect(adminPage.getByRole('heading', { name: template.name })).toBeVisible();
    for (const [name, op] of [
      ['Edit Template', UPDATE_OP],
      ['Create Profile from Template', PROFILE_OP],
      ['Delete template', DELETE_OP],
    ] as const) {
      await expectGate(adminPage.getByRole('button', { name, exact: true }), op, listed.get(op));
    }

    if (seeded) await sdk.device.deleteTemplate(seeded);
  });

  test('a template is renamed, used for a profile and deleted through its pages', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c as Capability]),
    );
    const writable = listed.get(CREATE_OP)?.enabled === true && listed.get(UPDATE_OP)?.enabled === true;

    if (!writable) {
      // The server does not offer the writes: the page withholds them.
      await adminPage.goto('/devices/templates');
      const create = adminPage.getByRole('button', { name: 'Create Template', exact: true });
      await expect(create).toHaveAttribute('data-capability-op', CREATE_OP);
      if (listed.get(CREATE_OP)?.enabled !== true) {
        await expectGate(create, CREATE_OP, listed.get(CREATE_OP));
      } else {
        const created = await sdk.device.createTemplate({
          name: `e2e-template-${Date.now()}`,
          role: 'worker',
        });
        expect(created.success, JSON.stringify(created.error)).toBeTruthy();
        const id = (created.data as ListedTemplate).id;
        await adminPage.goto(`/devices/templates/${id}`);
        await expectGate(
          adminPage.getByRole('button', { name: 'Edit Template', exact: true }),
          UPDATE_OP,
          listed.get(UPDATE_OP),
        );
        await sdk.device.deleteTemplate(id);
      }
      return;
    }

    const name = `e2e-template-${Date.now()}`;
    const created = await sdk.device.createTemplate({ name, role: 'worker' });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const id = (created.data as ListedTemplate).id;

    // Rename through the Edit template dialog.
    await adminPage.goto(`/devices/templates/${id}`);
    await expect(adminPage.getByRole('heading', { name })).toBeVisible();
    await adminPage.getByRole('button', { name: 'Edit Template', exact: true }).click();
    const dialog = adminPage.getByRole('dialog', { name: 'Edit template' });
    await expect(dialog).toBeVisible();
    const renamed = `${name}-v2`;
    await dialog.getByLabel('Name', { exact: true }).fill(renamed);
    await dialog.getByRole('button', { name: 'Save template' }).click();
    await expect(dialog).toBeHidden();
    await expect(adminPage.getByRole('heading', { name: renamed })).toBeVisible();
    const afterRename = await sdk.device.getTemplate(id);
    expect(afterRename.success, JSON.stringify(afterRename.error)).toBeTruthy();
    expect(afterRename.data?.name).toBe(renamed);

    // Create Profile from Template opens the form for this template.
    const profileButton = adminPage.getByRole('button', {
      name: 'Create Profile from Template',
      exact: true,
    });
    if (listed.get(PROFILE_OP)?.enabled === true) {
      await profileButton.click();
      await expect(adminPage).toHaveURL(new RegExp(`/devices/templates/${id}/create-profile`));
      await expect(adminPage.getByText(renamed).first()).toBeVisible();
      await adminPage.goto(`/devices/templates/${id}`);
      await expect(adminPage.getByRole('heading', { name: renamed })).toBeVisible();
    } else {
      await expectGate(profileButton, PROFILE_OP, listed.get(PROFILE_OP));
    }

    // Delete from the detail page.
    const deleteButton = adminPage.getByRole('button', { name: 'Delete template', exact: true });
    if (listed.get(DELETE_OP)?.enabled === true) {
      await deleteButton.click();
      await adminPage.getByRole('button', { name: 'Delete Template', exact: true }).click();
      await expect(adminPage).toHaveURL(/\/devices\/templates\/?$/);
      const gone = await sdk.device.getTemplate(id);
      expect(gone.success).toBeFalsy();
    } else {
      await expectGate(deleteButton, DELETE_OP, listed.get(DELETE_OP));
    }
  });

  test('a template is created through the Create Template dialog', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c as Capability]),
    );

    await adminPage.goto('/devices/templates');
    const trigger = adminPage.getByRole('button', { name: 'Create Template', exact: true });
    if (listed.get(CREATE_OP)?.enabled !== true) {
      await expectGate(trigger, CREATE_OP, listed.get(CREATE_OP));
      return;
    }

    await trigger.click();
    const dialog = adminPage.getByRole('dialog', { name: 'Create Device Template' });
    await expect(dialog).toBeVisible();
    const name = `e2e-template-dialog-${Date.now()}`;
    await dialog.getByLabel('Template Name', { exact: true }).fill(name);
    const created = apiWrite(adminPage, 'POST', '/api/v1/device/templates');
    await dialog.getByRole('button', { name: 'Create Template', exact: true }).click();
    const answer = await created;
    expect(answer.ok(), `create answered ${answer.status()}`).toBeTruthy();
    const id = createdId(unwrapPayload<unknown>(await answer.json()));

    try {
      await expect(dialog).toBeHidden();
      await expect(adminPage.getByText(name, { exact: true }).first()).toBeVisible();
      const viaSdk = await sdk.device.getTemplate(id);
      expect(viaSdk.success, JSON.stringify(viaSdk.error)).toBeTruthy();
      expect(viaSdk.data?.name).toBe(name);
    } finally {
      await sdk.device.deleteTemplate(id);
    }
  });

  test('a profile is created through the Create Profile from Template form', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const listed = new Map<string, Capability>(
      (res.data?.capabilities ?? []).map((c) => [c.op, c as Capability]),
    );

    if (listed.get(CREATE_OP)?.enabled !== true || listed.get(PROFILE_OP)?.enabled !== true) {
      // A template to open: one the server lists, else the create gate is all there is.
      const existing = await sdk.device.listTemplates();
      const template = existing.success ? templatesOf(existing.data)[0] : undefined;
      if (!template) {
        await adminPage.goto('/devices/templates');
        await expectGate(
          adminPage.getByRole('button', { name: 'Create Template', exact: true }),
          CREATE_OP,
          listed.get(CREATE_OP),
        );
        return;
      }
      await adminPage.goto(`/devices/templates/${template.id}/create-profile`);
      await expectGate(
        adminPage.getByRole('button', { name: 'Create Profile', exact: true }),
        PROFILE_OP,
        listed.get(PROFILE_OP),
      );
      return;
    }

    const created = await sdk.device.createTemplate({
      name: `e2e-template-profile-${Date.now()}`,
      role: 'worker',
    });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const templateId = String((created.data as ListedTemplate).id);
    let profileId: string | undefined;

    try {
      await adminPage.goto(`/devices/templates/${templateId}/create-profile`);
      const mac = uniqueMac();
      await adminPage.getByLabel('MAC Address', { exact: true }).fill(mac);
      const posted = apiWrite(
        adminPage,
        'POST',
        new RegExp(`^/api/v1/device/templates/${templateId}/create-profile$`),
      );
      await adminPage.getByRole('button', { name: 'Create Profile', exact: true }).click();
      const answer = await posted;
      expect(answer.ok(), `create-profile answered ${answer.status()}`).toBeTruthy();
      profileId = createdId(unwrapPayload<unknown>(await answer.json()));
      await expect(adminPage.getByRole('heading', { name: 'Profile Created' })).toBeVisible();

      const viaSdk = await sdk.device.getProfile(profileId);
      expect(viaSdk.success, JSON.stringify(viaSdk.error)).toBeTruthy();
      expect(profileOf(viaSdk.data)?.mac_address).toBe(mac);
    } finally {
      if (profileId) await sdk.device.deleteProfile(profileId);
      await sdk.device.deleteTemplate(templateId);
    }
  });
});
