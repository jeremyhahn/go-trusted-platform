import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload, wireCount } from './fixtures/wire';

/**
 * TPM event log, PCR extend, credential and random pages against the real
 * platformd and its simulator TPM (#2069, epic #1665).
 *
 * No page.route: every assertion compares the page with what the server
 * answered the page itself, and every gated control must be offered by the
 * server's capabilities (data-capability-enabled="true").
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

function base64ToHex(b64: string): string {
  return Array.from(Buffer.from(b64, 'base64'), (b) => b.toString(16).padStart(2, '0')).join('');
}

const DEBUG_PCR = 16;

test.describe('TPM event log', () => {
  test('shows the event count the server answered', async ({ adminPage }) => {
    const logRes = apiResponse(adminPage, 'GET', /\/api\/v1\/tpm\/eventlog$/);
    await adminPage.goto('/tpm/eventlog');
    const log = await json<{ eventCount?: number | string; entries?: unknown[] }>(await logRes);
    const count = log.eventCount === undefined ? 0 : wireCount(log.eventCount);
    const total = count || (log.entries?.length ?? 0);

    const card = adminPage.locator('div').filter({ hasText: /^Total Events/ }).first();
    await expect(card).toBeVisible();
    await expect(card).toContainText(String(total));
  });
});

test.describe('TPM PCR extend', () => {
  test('extending debug PCR 16 in the SHA-256 bank changes its value', async ({ adminPage }) => {
    const firstRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/pcrs$/);
    await adminPage.goto('/tpm/pcrs');
    const first = await json<{ pcrValues?: Array<{ index?: number; value?: string }> }>(await firstRes);
    const before = first.pcrValues?.find((p) => (p.index ?? 0) === DEBUG_PCR)?.value;
    expect(before, 'the first POST /api/v1/tpm/pcrs answered no PCR 16').toBeDefined();
    const beforeHex = base64ToHex(before as string);

    await adminPage.getByLabel('PCR index').fill(String(DEBUG_PCR));
    await adminPage.getByLabel('Data').fill(`e2e-${Date.now()}`);
    const extend = adminPage.getByRole('button', { name: 'Extend PCR' });
    await expect(extend).toHaveAttribute('data-capability-enabled', 'true');
    await extend.click();

    const extendRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/pcrs\/extend$/);
    const reloadRes = apiResponse(adminPage, 'POST', /\/api\/v1\/tpm\/pcrs$/);
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await json(await extendRes);
    const after = await json<{ pcrValues?: Array<{ index?: number; value?: string }> }>(await reloadRes);
    const afterValue = after.pcrValues?.find((p) => (p.index ?? 0) === DEBUG_PCR)?.value;
    expect(afterValue).toBeDefined();
    const afterHex = base64ToHex(afterValue as string);
    expect(afterHex).not.toBe(beforeHex);

    await expect(adminPage.getByText(afterHex, { exact: true })).toBeVisible();
  });
});

test.describe('TPM credential and random', () => {
  test('draws 16 random bytes', async ({ adminPage }) => {
    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('Number of bytes').fill('16');
    const random = adminPage.getByRole('button', { name: 'Get Random' });
    await expect(random).toHaveAttribute('data-capability-enabled', 'true');
    await random.click();
    await expect(adminPage.getByTestId('random-bytes')).toHaveText(/^[0-9a-f]{32}$/);
  });

  test('makes then activates a credential for the AK', async ({ adminPage, sdk }) => {
    const ak = await sdk.tpm.getAK();
    expect(ak.success, JSON.stringify(ak.error)).toBeTruthy();
    // GetAKResponse carries the public key, handle and algorithm; the AK
    // name MakeCredential needs is read when the server adds it.
    const akName = (ak.data as { name?: string } | undefined)?.name;
    test.skip(!akName, 'GetAK answers no AK name to make a credential for (#2069 gap)');

    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('AK name (base64)').fill(akName as string);
    await adminPage.getByLabel('Secret (optional)').fill('e2e-secret');
    const make = adminPage.getByRole('button', { name: 'Make Credential' });
    await expect(make).toHaveAttribute('data-capability-enabled', 'true');
    await make.click();
    const made = await adminPage.getByTestId('wrapped-secret').textContent();
    expect(made).toBeTruthy();

    const activate = adminPage.getByRole('button', { name: 'Activate Credential' });
    await expect(activate).toHaveAttribute('data-capability-enabled', 'true');
    await activate.click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('activated-secret')).toHaveText(made as string);
  });
});
