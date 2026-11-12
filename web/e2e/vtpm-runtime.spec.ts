import { test, expect, Page } from '@playwright/test';
import { createTenantOwnerSession } from './fixtures/auth-setup';
import { mockTenantApi, mockHealthApi, mockVTPMRuntimeApi, VTPMRuntimeCall } from './fixtures/api-mock';

/**
 * vTPM runtime page (#1726): every bundle runtime operation is reachable
 * from /tpm/vtpm/{id} and drives the mocked REST route.
 *
 * The page is opened at the nav entry's placeholder path (static export
 * ships only that one), and the bundle id is typed in.
 */

const BUNDLE = 'vm-1';

async function openRuntimePage(page: Page): Promise<VTPMRuntimeCall[]> {
  await mockTenantApi(page);
  await mockHealthApi(page);
  const { calls } = await mockVTPMRuntimeApi(page);
  await page.goto('/tpm/vtpm/__placeholder__/');
  await expect(page.getByRole('heading', { name: 'vTPM Runtime' })).toBeVisible();
  await page.getByLabel('Bundle ID').fill(BUNDLE);
  return calls;
}

function lastCall(calls: VTPMRuntimeCall[], path: string): VTPMRuntimeCall | undefined {
  return [...calls].reverse().find((c) => c.path === path);
}

test.describe('vTPM runtime page', () => {
  test.beforeEach(async ({ page }) => {
    await createTenantOwnerSession(page.context());
  });

  test('StartVTPM starts a bundle and shows it running', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await expect(page.getByTestId('vtpm-run-state')).toHaveText('Unknown');

    await page.getByRole('button', { name: 'Start vTPM' }).click();

    await expect(page.getByTestId('vtpm-run-state')).toHaveText('Running');
    await expect(page.getByTestId('vtpm-socket')).toHaveText(`/run/vtpm/${BUNDLE}.sock`);
    expect(lastCall(calls, 'start')?.method).toBe('POST');
  });

  test('StopVTPM stops a bundle after the confirm dialog', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await page.getByRole('button', { name: 'Start vTPM' }).click();
    await expect(page.getByTestId('vtpm-run-state')).toHaveText('Running');

    await page.getByRole('button', { name: 'Stop vTPM' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Stop this vTPM?');

    // Cancel sends nothing.
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await expect(dialog).toBeHidden();
    expect(lastCall(calls, 'stop')).toBeUndefined();

    await page.getByRole('button', { name: 'Stop vTPM' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm' }).click();

    await expect(page.getByTestId('vtpm-run-state')).toHaveText('Stopped');
    expect(lastCall(calls, 'stop')?.method).toBe('POST');
  });

  test('QuoteVTPM shows the quote', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await page.getByLabel('Nonce').fill('n0nce');
    await page.getByLabel('Quote PCRs').fill('0, 7');

    await page.getByRole('button', { name: 'Quote', exact: true }).click();

    const result = page.getByTestId('vtpm-quote-result');
    await expect(result).toContainText('Hash algorithm: SHA256');
    await expect(result).toContainText('PCR 7: aabb');
    expect(lastCall(calls, 'quote')?.body).toEqual({
      nonce: Buffer.from('n0nce').toString('base64'),
      pcrs: [0, 7],
    });
  });

  test('SealVTPM shows the sealed blob', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await page.getByLabel('Data to seal').fill('top secret');
    await page.getByLabel('Seal PCRs').fill('7');

    await page.getByRole('button', { name: 'Seal', exact: true }).click();

    await expect(page.getByTestId('vtpm-sealed-blob')).toHaveValue(
      Buffer.from('sealed:top secret').toString('base64')
    );
    expect(lastCall(calls, 'seal')?.body).toEqual({
      data: Buffer.from('top secret').toString('base64'),
      pcrs: [7],
    });
  });

  test('UnsealVTPM shows the unsealed data', async ({ page }) => {
    const calls = await openRuntimePage(page);
    const blob = Buffer.from('sealed:hello vtpm').toString('base64');
    await page.getByLabel('Sealed blob to unseal').fill(blob);

    await page.getByRole('button', { name: 'Unseal', exact: true }).click();

    await expect(page.getByTestId('vtpm-unsealed-data')).toContainText('hello vtpm');
    expect(lastCall(calls, 'unseal')?.body).toEqual({ sealed_data: blob });
  });

  test('ExtendVTPMPCR extends a PCR after the confirm dialog', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await page.getByLabel('Extend PCR index').fill('16');
    await page.getByLabel('Digest (hex)').fill('00ff');

    await page.getByRole('button', { name: 'Extend PCR' }).click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText('Extend this PCR?');
    expect(lastCall(calls, 'pcrs/extend')).toBeUndefined();
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect(page.getByTestId('vtpm-extend-result')).toHaveText('PCR 16 extended');
    expect(lastCall(calls, 'pcrs/extend')?.body).toEqual({
      pcr_index: 16,
      data: Buffer.from([0x00, 0xff]).toString('base64'),
    });
  });

  test('ReadVTPMPCR shows the PCR value', async ({ page }) => {
    const calls = await openRuntimePage(page);
    await page.getByLabel('Read PCR index').fill('7');

    await page.getByRole('button', { name: 'Read PCR' }).click();

    await expect(page.getByTestId('vtpm-pcr-value')).toHaveText('PCR 7: deadbeef');
    const call = lastCall(calls, 'pcrs');
    expect(call?.method).toBe('GET');
    expect(call?.query).toBe('?pcr_index=7');
  });
});
