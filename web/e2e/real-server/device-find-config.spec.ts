import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The Find config page and device profile assignment against the real
 * platformd (#2049, epic #1665). No page.route mocks: each assertion compares
 * the page with what the server answered the page itself, or with the
 * capabilities the server lists, not with a fixed state.
 */

/** The reason the capability gate shows for an op the server does not list. */
const NOT_OFFERED = 'not offered by this server';

const PAGE = '/devices/profiles/find-config';
const ASSIGN_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/assign';
const UNASSIGN_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/unassign';
const CREATE_TEMPLATE_OP = 'POST /api/v1/device/templates';
const CREATE_PROFILE_OP = 'POST /api/v1/device/templates/{id:[0-9]+}/create-profile';

/** The profile fields this spec reads from an SDK answer. */
interface ProfileFields {
  id: string;
  name: string;
  mac_address?: string;
}

/** A profile answer, bare or wrapped in { profile }. */
function profileOf(data: unknown): ProfileFields | undefined {
  const wrapped = (data as { profile?: ProfileFields } | undefined)?.profile;
  return wrapped ?? (data as ProfileFields | undefined);
}

/** A locally administered MAC (02:00:00 prefix) unique to this run. */
function uniqueMac(): string {
  const n = Date.now();
  const octet = (shift: number) => ((n >> shift) & 0xff).toString(16).padStart(2, '0');
  return `02:00:00:${octet(16)}:${octet(8)}:${octet(0)}`;
}

/** Waits for the page's own request with this method on exactly this path. */
function apiResponse(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname === path,
  );
}

/** errorText is the refusal message in a server error body, when it carries one. */
function errorText(body: unknown): string | undefined {
  if (body === null || typeof body !== 'object') return undefined;
  const b = body as { error?: unknown; message?: unknown };
  if (typeof b.error === 'string' && b.error !== '') return b.error;
  if (b.error !== null && typeof b.error === 'object') {
    const m = (b.error as { message?: unknown }).message;
    if (typeof m === 'string' && m !== '') return m;
  }
  if (typeof b.message === 'string' && b.message !== '') return b.message;
  return undefined;
}

test.describe('Find config page', () => {
  test('a lookup shows what the server answered for the device', async ({ adminPage }) => {
    await adminPage.goto(PAGE);
    // The Assign card below the lookup form reuses the EK serial label.
    await adminPage.getByLabel('EK serial').first().fill('EK-E2E-NONE');
    const found = apiResponse(adminPage, 'GET', '/api/v1/device/profiles/find-config');
    await adminPage.getByRole('button', { name: 'Find config', exact: true }).click();
    const res = await found;

    if (res.status() === 404) {
      await expect(adminPage.getByText('No profile matches this device.')).toBeVisible();
    } else if (!res.ok()) {
      await expect(adminPage.getByRole('alert').filter({ hasText: 'Lookup refused:' })).toBeVisible();
    } else {
      const profile = unwrapPayload<{ name: string }>(await res.json());
      await expect(adminPage.getByText(profile.name, { exact: true })).toBeVisible();
    }
  });

  test('Assign profile is gated on the server\'s capabilities', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const cap = (res.data?.capabilities ?? []).find((c) => c.op === ASSIGN_OP);
    const enabled = cap?.enabled === true;

    await adminPage.goto(PAGE);
    const button = adminPage.getByRole('button', { name: 'Assign profile', exact: true });
    await expect(button).toHaveAttribute('data-capability-op', ASSIGN_OP);
    await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
    if (!enabled) {
      await expect(button).toBeDisabled();
      await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
    }
  });

  test('assigning a profile that does not exist shows the server\'s refusal', async ({
    adminPage,
    sdk,
  }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const cap = (res.data?.capabilities ?? []).find((c) => c.op === ASSIGN_OP);

    await adminPage.goto(PAGE);
    const button = adminPage.getByRole('button', { name: 'Assign profile', exact: true });
    if (cap?.enabled !== true) {
      // The gate holds the control: the server would never see the request.
      await expect(button).toBeDisabled();
      return;
    }

    await adminPage.getByLabel('Profile ID', { exact: true }).fill('999999999');
    // The lookup form's MAC field comes first; the card's is the last one.
    await adminPage.getByLabel('MAC address', { exact: true }).last().fill('02:00:00:00:00:01');
    const assigned = apiResponse(adminPage, 'POST', '/api/v1/device/profiles/999999999/assign');
    await button.click();
    const answer = await assigned;

    expect(answer.ok(), `assign answered ${answer.status()}`).toBeFalsy();
    const alert = adminPage.getByRole('alert').filter({ hasText: 'Assignment refused:' });
    await expect(alert).toBeVisible();
    const message = errorText(await answer.json().catch(() => undefined));
    if (message !== undefined) {
      await expect(alert).toContainText(message);
    }
  });

  test('a profile is assigned, found and unassigned through the page', async ({ adminPage, sdk }) => {
    const res = await sdk.capabilities.list();
    expect(res.success, JSON.stringify(res.error)).toBeTruthy();
    const caps = res.data?.capabilities ?? [];
    const on = (op: string) => caps.find((c) => c.op === op)?.enabled === true;

    if (![CREATE_TEMPLATE_OP, CREATE_PROFILE_OP, ASSIGN_OP, UNASSIGN_OP].every(on)) {
      // Without every write the round trip needs, only the Assign gate is checked.
      const cap = caps.find((c) => c.op === ASSIGN_OP);
      const enabled = cap?.enabled === true;
      await adminPage.goto(PAGE);
      const button = adminPage.getByRole('button', { name: 'Assign profile', exact: true });
      await expect(button).toHaveAttribute('data-capability-op', ASSIGN_OP);
      await expect(button).toHaveAttribute('data-capability-enabled', enabled ? 'true' : 'false');
      if (!enabled) {
        await expect(button).toBeDisabled();
        await expect(button).toHaveAttribute('title', cap ? (cap.reason ?? '') : NOT_OFFERED);
      }
      return;
    }

    const name = `e2e-assign-${Date.now()}`;
    const template = await sdk.device.createTemplate({ name, role: 'worker' });
    expect(template.success, JSON.stringify(template.error)).toBeTruthy();
    const templateId = String((template.data as { id: string }).id);
    const created = await sdk.device.createProfileFromTemplate({ templateId });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const profile = profileOf(created.data);
    expect(profile?.id, 'the created profile carries an id').toBeTruthy();
    const profileId = String(profile?.id);
    const mac = uniqueMac();

    try {
      await adminPage.goto(PAGE);

      // Assign through the card.
      await adminPage.getByLabel('Profile ID', { exact: true }).fill(profileId);
      await adminPage.getByLabel('MAC address', { exact: true }).last().fill(mac);
      const assigned = apiResponse(adminPage, 'POST', `/api/v1/device/profiles/${profileId}/assign`);
      await adminPage.getByRole('button', { name: 'Assign profile', exact: true }).click();
      const assignAnswer = await assigned;
      expect(assignAnswer.ok(), `assign answered ${assignAnswer.status()}`).toBeTruthy();
      const assignedName = profile?.name ?? '';
      // The toast repeats the line; the card's own line is the paragraph.
      await expect(
        adminPage.locator('p').filter({ hasText: `Profile ${assignedName} assigned` }),
      ).toBeVisible();

      // Find it through the lookup form.
      await adminPage.getByLabel('MAC address', { exact: true }).first().fill(mac);
      const found = apiResponse(adminPage, 'GET', '/api/v1/device/profiles/find-config');
      await adminPage.getByRole('button', { name: 'Find config', exact: true }).click();
      const findAnswer = await found;
      expect(findAnswer.ok(), `find-config answered ${findAnswer.status()}`).toBeTruthy();
      await expect(adminPage.getByText(`Profile ID ${profileId}`, { exact: true })).toBeVisible();
      await expect(adminPage.getByText('Assigned', { exact: true })).toBeVisible();

      // Unassign is gated, and unassigns after the confirm.
      const unassign = adminPage.getByRole('button', { name: 'Unassign', exact: true }).first();
      await expect(unassign).toHaveAttribute('data-capability-op', UNASSIGN_OP);
      await expect(unassign).toHaveAttribute('data-capability-enabled', 'true');
      await unassign.click();
      const dialog = adminPage.getByRole('dialog', { name: 'Unassign profile?' });
      await expect(dialog).toBeVisible();
      const unassigned = apiResponse(adminPage, 'POST', `/api/v1/device/profiles/${profileId}/unassign`);
      await dialog.getByRole('button', { name: 'Unassign', exact: true }).click();
      const unassignAnswer = await unassigned;
      expect(unassignAnswer.ok(), `unassign answered ${unassignAnswer.status()}`).toBeTruthy();
      await expect(dialog).toBeHidden();
      await expect(adminPage.getByText('Not assigned', { exact: true })).toBeVisible();

      const after = await sdk.device.getProfile(profileId);
      expect(after.success, JSON.stringify(after.error)).toBeTruthy();
      expect(profileOf(after.data)?.mac_address ?? '').toBe('');
    } finally {
      await sdk.device.deleteProfile(profileId);
      await sdk.device.deleteTemplate(templateId);
    }
  });
});
