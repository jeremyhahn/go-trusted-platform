import { test, expect } from './fixtures';

/**
 * TPM operations against the real server.
 *
 * Ported from web/e2e/tpm-ops.spec.ts (#2037). The mocked spec recorded the
 * request bodies; here PCR 16 is read through sdk.tpm.getPCRs before and
 * after the UI action, and the random-bytes output comes from the server.
 * MakeCredential / ActivateCredential with a canned AK name and canned blobs
 * had no server behaviour behind them (the SDK exposes no AK name to seed a
 * real credential) and are listed as gaps in the PR body.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function readPCR16(sdk: any): Promise<string> {
  const res = await sdk.tpm.getPCRs({ indices: [16] });
  if (!res.success || !res.data) {
    throw new Error(`tpm.getPCRs failed: ${JSON.stringify(res.error)}`);
  }
  const pcr = (res.data.pcrValues as { index: number; value: string }[]).find((p) => p.index === 16);
  if (!pcr) throw new Error('PCR 16 missing from tpm.getPCRs');
  return pcr.value;
}

test.describe('TPM operations (real server)', () => {
  test('GetEventLog: event log page loads the log', async ({ adminPage, sdk }) => {
    const res = await sdk.tpm.getEventLog();
    expect(res.success).toBe(true);

    await adminPage.goto('/tpm/eventlog');

    await expect(adminPage.getByRole('heading', { name: 'TPM Event Log' })).toBeVisible();
  });

  test('ExtendPCR: confirming changes PCR 16 on the server', async ({ adminPage, sdk }) => {
    const before = await readPCR16(sdk);

    await adminPage.goto('/tpm/pcrs');
    await adminPage.getByLabel('PCR index').fill('16');
    await adminPage.getByLabel('Data', { exact: true }).fill(`measure-me-${Date.now()}`);
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog.getByText('Extend PCR 16?')).toBeVisible();
    await dialog.getByRole('button', { name: 'Confirm' }).click();

    await expect.poll(() => readPCR16(sdk)).not.toBe(before);
  });

  test('ExtendPCR: cancel leaves PCR 16 unchanged', async ({ adminPage, sdk }) => {
    const before = await readPCR16(sdk);

    await adminPage.goto('/tpm/pcrs');
    await adminPage.getByLabel('PCR index').fill('16');
    await adminPage.getByLabel('Data', { exact: true }).fill('measure-me');
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();
    await adminPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();

    await expect(adminPage.getByRole('dialog')).toBeHidden();
    expect(await readPCR16(sdk)).toBe(before);
  });

  test('GetRandom: credential page shows server random bytes', async ({ adminPage }) => {
    await adminPage.goto('/tpm/credential');

    await adminPage.getByLabel('Number of bytes').fill('4');
    await adminPage.getByRole('button', { name: 'Get Random' }).click();

    await expect(adminPage.getByTestId('random-bytes')).toHaveText(/^[0-9a-f]{8}$/i);
  });

  test('credential page is linked from the TPM nav', async ({ adminPage }) => {
    await adminPage.goto('/tpm/pcrs');

    const link = adminPage.getByRole('link', { name: 'Credential / Random' });
    await expect(link).toHaveAttribute('href', '/tpm/credential');
  });
});
