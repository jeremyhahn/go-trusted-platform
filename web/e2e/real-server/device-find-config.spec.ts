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
});
