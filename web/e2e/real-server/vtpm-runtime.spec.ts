import { test, expect } from './fixtures';
import type { Page } from '@playwright/test';

/**
 * vTPM runtime page against the real server.
 *
 * Ported from web/e2e/vtpm-runtime.spec.ts (#2037). Each test creates its own
 * bundle through sdk.vtpm.createBundle, drives the runtime page with that
 * bundle id, and checks the result against what the server reports through
 * the SDK (socket path, PCR reads). The mocked late-reply, bundle-switch race,
 * start/stop serialization timing and daemon-listener /pcr/{index} variant had
 * no server behaviour behind them and are listed as gaps in the PR body.
 */

const unique = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function must<T>(res: { success: boolean; data?: T; error?: any }, what: string): T {
  if (!res.success || res.data === undefined) {
    throw new Error(`${what} failed: ${JSON.stringify(res.error)}`);
  }
  return res.data;
}

const b64ToHex = (b64: string): string => Buffer.from(b64, 'base64').toString('hex');

const created: string[] = [];

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function newBundle(sdk: any): Promise<string> {
  const res = must(
    await sdk.vtpm.createBundle({ options: { hostname: unique('vtpm-e2e') } }),
    'vtpm.createBundle',
  ) as { id: string };
  created.push(res.id);
  return res.id;
}

async function openRuntime(page: Page, bundleId: string): Promise<void> {
  await page.goto('/tpm/vtpm/__placeholder__/');
  await expect(page.getByRole('heading', { name: 'vTPM Runtime' })).toBeVisible();
  await page.getByLabel('Bundle ID').fill(bundleId);
}

async function startFromUI(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Start vTPM' }).click();
  await expect(page.getByTestId('vtpm-run-state')).toHaveText('Running');
}

test.afterEach(async ({ sdk }) => {
  while (created.length > 0) {
    const id = created.pop() as string;
    await sdk.vtpm.stopBundle(id);
    await sdk.vtpm.deleteBundle(id);
  }
});

test.describe('vTPM runtime (real server)', () => {
  test('StartVTPM starts a bundle and shows the server socket path', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Unknown');

    await startFromUI(adminPage);

    const socket = must(await sdk.vtpm.getTPMSocketPath(id), 'vtpm.getTPMSocketPath');
    await expect(adminPage.getByTestId('vtpm-socket')).toHaveText(socket.path);
  });

  test('StopVTPM stops a bundle after the confirm dialog', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);
    await startFromUI(adminPage);

    await adminPage.getByRole('button', { name: 'Stop vTPM' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Stop this vTPM?');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');
    // Still running on the server: a PCR read succeeds.
    must(await sdk.vtpm.readBundlePCR(id, 0), 'vtpm.readBundlePCR');

    await adminPage.getByRole('button', { name: 'Stop vTPM' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Stopped');
  });

  test('QuoteVTPM shows the quote the server signs', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);
    await startFromUI(adminPage);
    const pcr7 = b64ToHex(must(await sdk.vtpm.readBundlePCR(id, 7), 'vtpm.readBundlePCR').value);

    await adminPage.getByLabel('Nonce').fill('n0nce');
    await adminPage.getByLabel('Quote PCRs').fill('0, 7');
    await adminPage.getByRole('button', { name: 'Quote', exact: true }).click();

    const result = adminPage.getByTestId('vtpm-quote-result');
    await expect(result).toContainText(/Hash algorithm: SHA-?256/i);
    await expect(result).toContainText(`PCR 7: ${pcr7}`);
  });

  test('SealVTPM then UnsealVTPM round-trips the data', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    const secret = unique('top secret');
    await openRuntime(adminPage, id);
    await startFromUI(adminPage);

    await adminPage.getByLabel('Data to seal').fill(secret);
    await adminPage.getByLabel('Seal PCRs').fill('7');
    await adminPage.getByRole('button', { name: 'Seal', exact: true }).click();

    const sealed = adminPage.getByTestId('vtpm-sealed-blob');
    await expect(sealed).not.toHaveValue('');
    const blob = await sealed.inputValue();

    await adminPage.getByLabel('Sealed blob to unseal').fill(blob);
    await adminPage.getByRole('button', { name: 'Unseal', exact: true }).click();
    await expect(adminPage.getByTestId('vtpm-unsealed-data')).toContainText(secret);

    // The server unseals the same blob to the same data.
    const unsealed = must(await sdk.vtpm.unsealBundle(id, { sealed_data: blob }), 'vtpm.unsealBundle');
    expect(Buffer.from(unsealed.data, 'base64').toString('utf8')).toBe(secret);
  });

  test('ExtendVTPMPCR changes PCR 16 on the server after the confirm', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);
    await startFromUI(adminPage);
    const read16 = async (): Promise<string> =>
      must(await sdk.vtpm.readBundlePCR(id, 16), 'vtpm.readBundlePCR').value;
    const before = await read16();

    await adminPage.getByLabel('Extend PCR index').fill('16');
    await adminPage.getByLabel('Data to extend (hex)').fill('00ff');
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();
    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toContainText('Extend this PCR?');
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect(adminPage.getByTestId('vtpm-extend-result')).toHaveText('PCR 16 extended');
    await expect.poll(read16).not.toBe(before);
  });

  test('ReadVTPMPCR shows the value the server reads', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);
    await startFromUI(adminPage);
    const pcr7 = b64ToHex(must(await sdk.vtpm.readBundlePCR(id, 7), 'vtpm.readBundlePCR').value);

    await adminPage.getByLabel('Read PCR index').fill('7');
    await adminPage.getByRole('button', { name: 'Read PCR' }).click();

    await expect(adminPage.getByTestId('vtpm-pcr-value')).toHaveText(`PCR 7: ${pcr7}`);
  });

  test('an empty extend index shows an error and leaves PCRs alone', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);

    await adminPage.getByLabel('Extend PCR index').fill('');
    await adminPage.getByLabel('Data to extend (hex)').fill('00ff');
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();

    await expect(adminPage.getByText('Enter exactly one PCR index (0-23)').first()).toBeVisible();
    await expect(adminPage.getByRole('dialog')).toBeHidden();
  });

  test('a list as the extend index shows an error', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);

    await adminPage.getByLabel('Extend PCR index').fill('1,2');
    await adminPage.getByLabel('Data to extend (hex)').fill('00ff');
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();

    await expect(adminPage.getByText('Enter exactly one PCR index (0-23)').first()).toBeVisible();
    await expect(adminPage.getByRole('dialog')).toBeHidden();
  });

  test('an empty read index shows an error and no value', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    await openRuntime(adminPage, id);

    await adminPage.getByLabel('Read PCR index').fill('');
    await adminPage.getByRole('button', { name: 'Read PCR' }).click();

    await expect(adminPage.getByText('Enter exactly one PCR index (0-23)').first()).toBeVisible();
    await expect(adminPage.getByTestId('vtpm-pcr-value')).toHaveCount(0);
  });

  test('switching bundles clears the previous bundle results', async ({ adminPage, sdk }) => {
    const first = await newBundle(sdk);
    const second = await newBundle(sdk);
    await openRuntime(adminPage, first);
    await startFromUI(adminPage);
    await adminPage.getByLabel('Read PCR index').fill('7');
    await adminPage.getByRole('button', { name: 'Read PCR' }).click();
    await expect(adminPage.getByTestId('vtpm-pcr-value')).toBeVisible();

    await adminPage.getByLabel('Bundle ID').fill(second);

    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Unknown');
    await expect(adminPage.getByTestId('vtpm-socket')).toHaveCount(0);
    await expect(adminPage.getByTestId('vtpm-pcr-value')).toHaveCount(0);
  });

  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/tpm/vtpm/__placeholder__/');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  // #2072: the page seeds its run state from GET /bundles/{id}/state.
  test('IsVTPMRunning shows Running for a bundle the server already started', async ({ adminPage, sdk }) => {
    const id = await newBundle(sdk);
    must(await sdk.vtpm.startBundle(id), 'vtpm.startBundle');
    await openRuntime(adminPage, id);
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');
  });
});
