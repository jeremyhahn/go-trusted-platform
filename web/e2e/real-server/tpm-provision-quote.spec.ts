import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * TPM provisioning and quote pages against the real platformd and its
 * simulator TPM (#2068, epic #1665).
 *
 * No page.route: every assertion compares the page with what the server
 * answered the page itself, and every gated control must be offered by the
 * server's capabilities (data-capability-enabled="true"). Provision TPM and
 * Clear TPM are never clicked: provisioning or clearing the shared simulator
 * TPM would break the other specs.
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

function handleHex(handle: number): string {
  return `0x${handle.toString(16).padStart(8, '0')}`;
}

/** The server's refusal message, whichever envelope carries it. */
async function refusalMessage(r: Response): Promise<string | undefined> {
  const body = (await r.json().catch(() => undefined)) as
    | { error?: { message?: string } | string; message?: string }
    | undefined;
  if (!body) return undefined;
  if (typeof body.error === 'string') return body.error;
  return body.error?.message ?? body.message;
}

test.describe('TPM provisioning', () => {
  test('shows the platform the server answered and offers Provision and Clear', async ({ adminPage }) => {
    const platformRes = apiResponse(adminPage, 'GET', /\/api\/v1\/tpm\/platform$/);
    await adminPage.goto('/tpm/provision');
    const platform = await json<{ device?: string; manufacturer?: string }>(await platformRes);

    await expect(adminPage.getByTestId('platform-device')).toHaveText(platform.device ?? '');
    await expect(adminPage.getByTestId('platform-manufacturer')).toHaveText(platform.manufacturer ?? '');

    const provision = adminPage.getByRole('button', { name: 'Provision TPM' });
    await expect(provision).toHaveAttribute('data-capability-op', 'POST /api/v1/tpm/provision');
    await expect(provision).toHaveAttribute('data-capability-enabled', 'true');
    const clear = adminPage.getByRole('button', { name: 'Clear TPM…' });
    await expect(clear).toHaveAttribute('data-capability-op', 'POST /api/v1/tpm/clear');
    await expect(clear).toHaveAttribute('data-capability-enabled', 'true');
  });
});

test.describe('TPM quote', () => {
  test('shows the AK and the quote the server answered', async ({ adminPage }) => {
    const akRes = apiResponse(adminPage, 'GET', /\/api\/v1\/tpm\/ak$/);
    await adminPage.goto('/tpm/quote');
    const firstAK = await akRes;

    if (firstAK.status() === 404) {
      const create = adminPage.getByRole('button', { name: /Create AK/ });
      await expect(create).toHaveAttribute('data-capability-enabled', 'true');
      const createRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/ak$/);
      const rereadRes = apiResponse(adminPage, 'GET', /\/api\/v1\/tpm\/ak$/);
      await create.click();
      const created = await json<{ handle?: number }>(await createRes);
      const reread = await json<{ handle?: number }>(await rereadRes);
      const handle = created.handle ?? reread.handle;
      expect(handle, 'POST /api/v1/tpm/ak answered no AK handle').toBeDefined();
      await expect(adminPage.getByTestId('ak-handle')).toHaveText(handleHex(handle as number));
    } else {
      const ak = await json<{ handle?: number }>(firstAK);
      expect(ak.handle, 'GET /api/v1/tpm/ak answered no AK handle').toBeDefined();
      await expect(adminPage.getByTestId('ak-handle')).toHaveText(handleHex(ak.handle as number));
    }

    await adminPage.getByRole('checkbox', { name: /^PCR 0\b/ }).check();
    const generate = adminPage.getByRole('button', { name: /Generate Quote/ });
    await expect(generate).toHaveAttribute('data-capability-enabled', 'true');
    const quoteRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/quote$/);
    await generate.click();
    const answered = await quoteRes;

    if (answered.ok()) {
      const quote = unwrapPayload<{ quote?: string }>(await answered.json());
      expect(quote.quote, 'POST /api/v1/tpm/quote answered no quote').toBeTruthy();
      await expect(adminPage.getByLabel('Attestation')).toHaveValue(quote.quote as string);
    } else {
      const message = await refusalMessage(answered);
      const toast = adminPage.getByTestId('toast').filter({ hasText: 'Quote failed' });
      await expect(toast).toBeVisible();
      if (message) await expect(toast).toContainText(message);
    }
  });
});
