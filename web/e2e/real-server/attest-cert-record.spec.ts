import type { Page, Response } from '@playwright/test';
import { test, expect } from './fixtures';

/**
 * "Record certificate" on the device detail page (#491), against the
 * real-server harness (#2035).
 *
 * POST /api/v1/devices/{id}/attest-cert/record records the device's
 * attestation certificate without re-enrolling; the server fails closed with
 * no override. The device is seeded through the SDK with an attestation key
 * the server cannot certify (a placeholder that does not parse as a key): the
 * page renders the certificate card for it, and the server refuses every
 * record attempt, so each case asserts on the request the console sends and on
 * the answer the server really gives.
 */

/** A placeholder attest_pub: the page shows the card, the server cannot parse it. */
const UNCERTIFIABLE_ATTEST_PUB = 'e2e-not-a-key';

/** The device the server answered: res.data is the device itself, not {device}. */
function deviceOf(data: unknown): { id?: string | number; attest_cert?: string } {
  return (data ?? {}) as { id?: string | number; attest_cert?: string };
}

/** The message of a platform error envelope, in either of its two shapes. */
function serverMessage(body: unknown): string {
  const b = body as { error?: string | { message?: string } } | null;
  if (typeof b?.error === 'string') return b.error;
  return b?.error?.message ?? '';
}

function isRecord(r: Response): boolean {
  return r.request().method() === 'POST' && /\/api\/v1\/devices\/[^/]+\/attest-cert\/record$/.test(new URL(r.url()).pathname);
}

/**
 * The device detail route is a static export: the build emits one page for
 * the `__placeholder__` id and the client resolves the real id from the URL.
 */
async function openDetail(page: Page, id: string): Promise<void> {
  await page.goto('/devices/__placeholder__/');
  await page.getByText('Loading device details').waitFor();
  await page.waitForLoadState('networkidle');
  await page.evaluate((deviceId) => window.history.pushState(null, '', `/devices/${deviceId}/`), id);
  await expect(page.getByTestId('attest-cert-card')).toBeVisible();
}

test.describe('Record attestation certificate (#491), real server', () => {
  let deviceId = '';

  test.beforeEach(async ({ sdk }) => {
    const serial = `e2e-acr-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
    const res = await sdk.device.createDevice({
      device: { serial, model: serial, attest_pub: UNCERTIFIABLE_ATTEST_PUB },
    });
    expect(res.success).toBe(true);
    deviceId = String(deviceOf(res.data).id ?? '');
    expect(deviceId).not.toBe('');
  });

  test.afterEach(async ({ sdk }) => {
    if (deviceId) await sdk.device.deleteDevice(deviceId).catch(() => undefined);
  });

  test('a device with no certificate says so and records without re-issuing by default', async ({ adminPage, sdk }) => {
    const before = await sdk.device.getDevice(deviceId);
    expect(deviceOf(before.data).attest_cert ?? '').toBe('');
    await openDetail(adminPage, deviceId);
    await expect(adminPage.getByTestId('attest-cert-absent')).toBeVisible();

    await adminPage.getByRole('button', { name: /record certificate/i }).click();
    await expect(adminPage.getByRole('checkbox', { name: /re-issue/i })).not.toBeChecked();
    const answer = adminPage.waitForResponse(isRecord);
    await adminPage.getByRole('button', { name: /^record$/i }).click();
    const res = await answer;
    expect((res.request().postDataJSON() as { reissue: boolean }).reissue).toBe(false);

    const body = await res.json().catch(() => null);
    if (res.ok()) {
      await expect(adminPage.getByText('Certificate recorded')).toBeVisible();
      const after = await sdk.device.getDevice(deviceId);
      expect(deviceOf(after.data).attest_cert ?? '').not.toBe('');
    } else {
      await expect(adminPage.getByTestId('attest-cert-refusal')).toHaveText(serverMessage(body));
    }
  });

  test('re-issuance is opt-in behind a confirm step that warns the CA will issue', async ({ adminPage }) => {
    await openDetail(adminPage, deviceId);

    await adminPage.getByRole('button', { name: /record certificate/i }).click();
    await expect(adminPage.getByTestId('attest-cert-reissue-warning')).toBeHidden();
    await adminPage.getByRole('checkbox', { name: /re-issue/i }).check();
    await expect(adminPage.getByTestId('attest-cert-reissue-warning')).toBeVisible();
    const answer = adminPage.waitForResponse(isRecord);
    await adminPage.getByRole('button', { name: /record and re-issue/i }).click();
    const res = await answer;
    expect((res.request().postDataJSON() as { reissue: boolean }).reissue).toBe(true);

    const body = await res.json().catch(() => null);
    if (res.ok()) {
      await expect(adminPage.getByText('Certificate recorded')).toBeVisible();
    } else {
      await expect(adminPage.getByTestId('attest-cert-refusal')).toHaveText(serverMessage(body));
    }
  });

  test('a device whose attestation key the server cannot certify is refused verbatim and nothing is recorded', async ({ adminPage, sdk }) => {
    await openDetail(adminPage, deviceId);

    await adminPage.getByRole('button', { name: /record certificate/i }).click();
    const answer = adminPage.waitForResponse(isRecord);
    await adminPage.getByRole('button', { name: /^record$/i }).click();
    const res = await answer;

    expect(res.ok()).toBe(false);
    const message = serverMessage(await res.json().catch(() => null));
    expect(message).not.toBe('');
    await expect(adminPage.getByTestId('attest-cert-refusal')).toHaveText(message);
    await adminPage.getByRole('button', { name: /cancel/i }).click();
    await expect(adminPage.getByTestId('attest-cert-absent')).toBeVisible();

    const after = await sdk.device.getDevice(deviceId);
    expect(deviceOf(after.data).attest_cert ?? '').toBe('');
  });
});
