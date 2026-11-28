import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * The TPM key lifecycle and certify cards on /tpm/keys against the real
 * platformd and its simulator TPM (#2068, epic #1665).
 *
 * No page.route: every assertion compares the page with what the server
 * answered the page itself, and every gated control must be offered by the
 * server's capabilities (data-capability-enabled="true"). Create, Evict,
 * Import and Evict AK are never clicked: they change the shared simulator TPM.
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

const LIFECYCLE_CONTROLS = ['Create EK', 'Evict EK', 'Create SRK', 'Evict SRK', 'Import certificate'];
const CERTIFY_CONTROLS = ['Certify', 'Evict AK'];

test.describe('TPM key cards', () => {
  test('the cards are offered and Certify answers what the server answered for the SRK', async ({ adminPage }) => {
    const srkRes = apiResponse(adminPage, 'GET', /\/api\/v1\/tpm\/srk$/);
    await adminPage.goto('/tpm/keys');
    const srk = await json<{ handle?: number }>(await srkRes);
    expect(srk.handle, 'GET /api/v1/tpm/srk answered no handle').toBeDefined();

    const lifecycle = adminPage.getByTestId('tpm-key-lifecycle-card');
    const certifyCard = adminPage.getByTestId('tpm-certify-card');
    await expect(lifecycle).toBeVisible();
    await expect(certifyCard).toBeVisible();

    for (const name of LIFECYCLE_CONTROLS) {
      await expect(lifecycle.getByRole('button', { name, exact: true })).toHaveAttribute(
        'data-capability-enabled',
        'true',
      );
    }
    for (const name of CERTIFY_CONTROLS) {
      await expect(certifyCard.getByRole('button', { name, exact: true })).toHaveAttribute(
        'data-capability-enabled',
        'true',
      );
    }

    await certifyCard.getByLabel('Key handle').fill(`0x${Number(srk.handle).toString(16)}`);
    const certifyRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/certify$/);
    await certifyCard.getByRole('button', { name: 'Certify', exact: true }).click();
    const res = await certifyRes;

    if (res.ok()) {
      const answer = unwrapPayload<{ signatureAlgorithm?: string }>(await res.json());
      const result = adminPage.getByTestId('tpm-certify-result');
      await expect(result).toBeVisible();
      await expect(result).toContainText(answer.signatureAlgorithm ?? '-');
    } else {
      const text = refusalText(await res.json().catch(() => null));
      const toast = adminPage.getByText(/Certify failed/).first();
      await expect(toast).toBeVisible();
      if (text) {
        await expect(toast).toContainText(text);
      }
      await expect(adminPage.getByTestId('tpm-certify-result')).toHaveCount(0);
    }
  });
});
