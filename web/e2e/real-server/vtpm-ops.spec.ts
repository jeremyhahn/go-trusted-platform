/**
 * vTPM runtime operations against the real server (#2072, epic #1665):
 * StartVTPM, StopVTPM, IsVTPMRunning, QuoteVTPM, SealVTPM, UnsealVTPM,
 * ExtendVTPMPCR and ReadVTPMPCR, driven from the runtime page at
 * /tpm/vtpm/<bundle>. State is seeded through the SDK and every assertion
 * is checked against what the server returns; no route mocks.
 */
import { test, expect } from './fixtures';

type SDK = {
  vtpm: {
    createBundle(req: unknown): Promise<{ success?: boolean; data?: unknown }>;
    deleteBundle(id: string): Promise<unknown>;
    stopBundle(id: string): Promise<unknown>;
    isBundleRunning(id: string): Promise<{ success?: boolean; data?: { running?: boolean } }>;
    readBundlePCR(id: string, pcr: number): Promise<{ data?: { value?: string } }>;
  };
};

function bundleIdOf(data: unknown): string {
  const d = (data ?? {}) as Record<string, unknown>;
  const nested = (d.bundle ?? {}) as Record<string, unknown>;
  const id = d.id ?? d.bundle_id ?? nested.id ?? nested.bundle_id;
  if (typeof id !== 'string' || id === '') {
    throw new Error(`create bundle returned no id: ${JSON.stringify(data)}`);
  }
  return id;
}

async function seedBundle(sdk: SDK, name: string): Promise<string> {
  const r = await sdk.vtpm.createBundle({ options: { name } });
  expect(r.success).toBe(true);
  return bundleIdOf(r.data);
}

async function serverRunning(sdk: SDK, id: string): Promise<boolean | undefined> {
  const r = await sdk.vtpm.isBundleRunning(id);
  return r.data?.running;
}

test.describe('vTPM runtime operations (real server)', () => {
  let bundleId = '';

  test.beforeEach(async ({ sdk }) => {
    bundleId = await seedBundle(sdk as unknown as SDK, `e2e-vtpm-ops-${Date.now()}`);
  });

  test.afterEach(async ({ sdk }) => {
    if (!bundleId) return;
    const s = sdk as unknown as SDK;
    await s.vtpm.stopBundle(bundleId).catch(() => undefined);
    await s.vtpm.deleteBundle(bundleId).catch(() => undefined);
  });

  test('a fresh bundle shows the server running state: stopped', async ({ adminPage, sdk }) => {
    expect(await serverRunning(sdk as unknown as SDK, bundleId)).toBe(false);
    await adminPage.goto(`/tpm/vtpm/${bundleId}`);
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Stopped');
  });

  test('start, reload, stop: the page and IsVTPMRunning agree', async ({ adminPage, sdk }) => {
    const s = sdk as unknown as SDK;
    await adminPage.goto(`/tpm/vtpm/${bundleId}`);
    await adminPage.getByRole('button', { name: 'Start vTPM' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');
    await expect.poll(() => serverRunning(s, bundleId)).toBe(true);

    // The state after a reload comes from IsVTPMRunning, not a start reply.
    await adminPage.reload();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');

    await adminPage.getByRole('button', { name: 'Stop vTPM' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Stopped');
    await expect.poll(() => serverRunning(s, bundleId)).toBe(false);
  });

  test('quote returns a signed quote over the chosen PCRs', async ({ adminPage }) => {
    await adminPage.goto(`/tpm/vtpm/${bundleId}`);
    await adminPage.getByRole('button', { name: 'Start vTPM' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');

    await adminPage.getByLabel('Nonce').fill('e2e-nonce');
    await adminPage.getByLabel('Quote PCRs').fill('0,7');
    await adminPage.getByRole('button', { name: 'Quote', exact: true }).click();
    const result = adminPage.getByTestId('vtpm-quote-result');
    await expect(result).toBeVisible();
    await expect(result).toContainText('PCR 0:');
    await expect(result).toContainText('PCR 7:');
  });

  test('seal then unseal returns the sealed text', async ({ adminPage }) => {
    await adminPage.goto(`/tpm/vtpm/${bundleId}`);
    await adminPage.getByRole('button', { name: 'Start vTPM' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');

    await adminPage.getByLabel('Data to seal').fill('e2e secret');
    await adminPage.getByLabel('Seal PCRs').fill('7');
    await adminPage.getByRole('button', { name: 'Seal', exact: true }).click();
    await expect(adminPage.getByTestId('vtpm-sealed-blob')).not.toHaveValue('');

    await adminPage.getByRole('button', { name: 'Unseal', exact: true }).click();
    await expect(adminPage.getByTestId('vtpm-unsealed-data')).toContainText('e2e secret');
  });

  test('read and extend a PCR: the extend changes the server value', async ({ adminPage, sdk }) => {
    const s = sdk as unknown as SDK;
    await adminPage.goto(`/tpm/vtpm/${bundleId}`);
    await adminPage.getByRole('button', { name: 'Start vTPM' }).click();
    await expect(adminPage.getByTestId('vtpm-run-state')).toHaveText('Running');

    await adminPage.getByLabel('Read PCR index').fill('16');
    await adminPage.getByRole('button', { name: 'Read PCR' }).click();
    await expect(adminPage.getByTestId('vtpm-pcr-value')).toContainText('PCR 16:');
    const before = (await s.vtpm.readBundlePCR(bundleId, 16)).data?.value;

    await adminPage.getByLabel('Extend PCR index').fill('16');
    await adminPage.getByLabel('Data to extend (hex)').fill('deadbeef');
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    await expect(adminPage.getByTestId('vtpm-extend-result')).toContainText('PCR 16 extended');

    const after = (await s.vtpm.readBundlePCR(bundleId, 16)).data?.value;
    expect(after).toBeTruthy();
    expect(after).not.toEqual(before);
  });
});
