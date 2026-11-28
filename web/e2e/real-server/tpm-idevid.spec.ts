import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The IDevID views and controls of /tpm/status against the real platformd and
 * its simulator TPM (#2055, epic #1665).
 *
 * No page.route: every assertion compares the page with what the server
 * answered the page itself, and every gated control must be offered by the
 * server's capabilities (data-capability-enabled="true"). Generate IAK, Delete
 * IAK, Flush, the installs, Delete IAK certificate and Create LDevID are never
 * clicked: they change the shared simulator TPM.
 */

function apiResponse(page: Page, method: string, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && path.test(new URL(r.url()).pathname),
  );
}

async function json<T>(r: Response): Promise<T> {
  expect(r.ok(), `${r.url()} answered ${r.status()}`).toBeTruthy();
  return unwrapPayload<T>(await r.json());
}

/** The refusal text a control-plane error body carries, if any. */
function refusalText(body: unknown): string | undefined {
  const b = body as { error?: { message?: string } | string; message?: string } | null;
  if (b && typeof b.error === 'object' && typeof b.error.message === 'string') return b.error.message;
  if (b && typeof b.error === 'string') return b.error;
  if (b && typeof b.message === 'string') return b.message;
  return undefined;
}

interface DeviceAttributes {
  tpmManufacturer?: string;
  tpmModel?: string;
  tpmVersion?: string;
}

const GATED_CONTROLS = [
  'Generate IAK',
  'Delete IAK',
  'Flush transient contexts',
  'Install IDevID certificate',
  'Install IAK certificate',
  'Delete IAK certificate',
  'Create LDevID',
  'Activate credential',
];

test.describe('TPM status IDevID', () => {
  test('the presence badges and device attributes show what the server answered', async ({ adminPage }) => {
    const idevidRes = apiResponse(adminPage, 'GET', /\/api\/v1\/idevid\/exists$/);
    const iakRes = apiResponse(adminPage, 'GET', /\/api\/v1\/idevid\/iak\/exists$/);
    const attrsRes = apiResponse(adminPage, 'GET', /\/api\/v1\/idevid\/attributes$/);
    await adminPage.goto('/tpm/status');

    const idevid = await json<{ exists?: boolean }>(await idevidRes);
    const iak = await json<{ exists?: boolean }>(await iakRes);
    await expect(adminPage.getByText(idevid.exists ? 'IDevID Present' : 'No IDevID', { exact: true })).toBeVisible();
    await expect(adminPage.getByText(iak.exists ? 'IAK Present' : 'No IAK', { exact: true })).toBeVisible();

    const attrs = await attrsRes;
    if (attrs.ok()) {
      const answer = unwrapPayload<DeviceAttributes>(await attrs.json());
      const card = adminPage.getByTestId('device-attributes');
      await expect(card).toBeVisible();
      for (const value of [answer.tpmManufacturer, answer.tpmModel, answer.tpmVersion]) {
        if (value) {
          await expect(card).toContainText(value);
        }
      }
    }
  });

  test('every IDevID control is offered by the server', async ({ adminPage }) => {
    await adminPage.goto('/tpm/status');
    await expect(adminPage.getByTestId('ldevid-card')).toBeVisible();
    await expect(adminPage.getByTestId('iak-cert-actions-card')).toBeVisible();

    for (const name of GATED_CONTROLS) {
      await expect(adminPage.getByRole('button', { name, exact: true })).toHaveAttribute(
        'data-capability-enabled',
        'true',
      );
    }
  });

  test('Activate credential answers what the server answered', async ({ adminPage }) => {
    await adminPage.goto('/tpm/status');
    const card = adminPage.getByTestId('iak-cert-actions-card');
    await expect(card).toBeVisible();

    await card.getByLabel('Credential blob (base64)').fill('AAAA');
    await card.getByLabel('Secret (base64)').fill('AAAA');
    const button = card.getByRole('button', { name: 'Activate credential', exact: true });
    await expect(button).toHaveAttribute('data-capability-enabled', 'true');
    const activateRes = apiResponse(adminPage, 'POST', /\/api\/v1\/idevid\/activate-credential$/);
    await button.click();
    const res = await activateRes;

    if (res.ok()) {
      await expect(adminPage.getByTestId('activate-secret')).toBeVisible();
    } else {
      const text = refusalText(await res.json().catch(() => null));
      const toast = adminPage.getByText(/Activate credential failed/).first();
      await expect(toast).toBeVisible();
      if (text) {
        await expect(toast).toContainText(text);
      }
      await expect(adminPage.getByTestId('activate-secret')).toHaveCount(0);
    }
  });
});
