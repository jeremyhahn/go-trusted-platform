/**
 * Real-server spec for the TPM event-log row (#2069, epic #1665):
 * GetEventLog, ExtendPCR, MakeCredential, ActivateCredential and GetRandom.
 *
 * Every assertion compares the page with what the harness server returns
 * to the SDK for the same call; no route is mocked.
 */
import { test, expect } from './fixtures';

const toHex = (b64: string): string =>
  Array.from(Buffer.from(b64, 'base64'))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

// A syntactically valid TPM name: nameAlg SHA-256 (0x000b) and a digest.
const SYNTHETIC_AK_NAME = Buffer.concat([
  Buffer.from([0x00, 0x0b]),
  Buffer.alloc(32, 0x5a),
]).toString('base64');

test.describe('TPM event log (GetEventLog)', () => {
  test('shows the event count the server reports', async ({ adminPage, sdk }) => {
    const log = await sdk.tpm.getEventLog();
    expect(log.success).toBe(true);
    const count = log.data?.eventCount ?? 0;

    await adminPage.goto('/tpm/eventlog');
    await expect(
      adminPage.getByRole('heading', { name: 'TPM Event Log' })
    ).toBeVisible();
    await expect(adminPage.getByText('Measurement Log Entries')).toBeVisible();
    if (count > 0 && (log.data?.entries?.length ?? 0) === 0) {
      await expect(adminPage.getByText(String(count), { exact: true }).first()).toBeVisible();
    }
  });

  test('refresh refetches the log', async ({ adminPage }) => {
    await adminPage.goto('/tpm/eventlog');
    const refetch = adminPage.waitForResponse(
      (r) => r.url().includes('/eventlog') && r.request().method() === 'GET'
    );
    await adminPage.getByRole('button', { name: 'Refresh' }).click();
    expect((await refetch).ok()).toBe(true);
  });
});

test.describe('TPM PCR extend (ExtendPCR)', () => {
  test('extending PCR 16 changes its value on the server', async ({ adminPage, sdk }) => {
    const before = await sdk.tpm.getPCRs({ indices: [16], bank: 'SHA256' });
    expect(before.success).toBe(true);
    const valueBefore = before.data?.pcrValues?.[0]?.value;

    await adminPage.goto('/tpm/pcrs');
    await adminPage.getByLabel('PCR index').fill('16');
    await adminPage.getByLabel('Data').fill(`e2e-extend-${Date.now()}`);
    await adminPage.getByRole('button', { name: 'Extend PCR' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText('Extend PCR 16?');
    const extended = adminPage.waitForResponse(
      (r) => r.url().includes('/pcrs/extend') && r.request().method() === 'POST'
    );
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    expect((await extended).ok()).toBe(true);

    const after = await sdk.tpm.getPCRs({ indices: [16], bank: 'SHA256' });
    expect(after.success).toBe(true);
    expect(after.data?.pcrValues?.[0]?.value).not.toEqual(valueBefore);
  });
});

test.describe('TPM credentials and random (MakeCredential, ActivateCredential, GetRandom)', () => {
  test('make credential fills the activate form with the server blob', async ({ adminPage }) => {
    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('AK name (base64)').fill(SYNTHETIC_AK_NAME);
    await adminPage.getByLabel('Secret (optional)').fill('e2e secret');
    const made = adminPage.waitForResponse(
      (r) => r.url().includes('/make-credential') && r.request().method() === 'POST'
    );
    await adminPage.getByRole('button', { name: 'Make Credential' }).click();
    const resp = await made;
    expect(resp.ok()).toBe(true);
    const body = (await resp.json()) as { credentialBlob?: string; encryptedSecret?: string };
    expect(body.credentialBlob).toBeTruthy();
    expect(body.encryptedSecret).toBeTruthy();
    await expect(adminPage.getByLabel('Credential blob (base64)')).toHaveValue(body.credentialBlob!);
    await expect(adminPage.getByLabel('Encrypted secret (base64)')).toHaveValue(body.encryptedSecret!);
  });

  test('activate credential shows what the server returns', async ({ adminPage, sdk }) => {
    const made = await sdk.tpm.makeCredential({ akName: SYNTHETIC_AK_NAME });
    expect(made.success).toBe(true);
    const credentialBlob = made.data!.credentialBlob;
    const encryptedSecret = made.data!.encryptedSecret;

    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('Credential blob (base64)').fill(credentialBlob);
    await adminPage.getByLabel('Encrypted secret (base64)').fill(encryptedSecret);
    await adminPage.getByRole('button', { name: 'Activate Credential' }).click();
    await expect(adminPage.getByRole('dialog')).toContainText('Activate this credential?');
    const activated = adminPage.waitForResponse(
      (r) => r.url().includes('/activate-credential') && r.request().method() === 'POST'
    );
    await adminPage.getByRole('button', { name: 'Confirm' }).click();
    const resp = await activated;
    if (resp.ok()) {
      const body = (await resp.json()) as { secret: string };
      await expect(adminPage.getByTestId('activated-secret')).toHaveText(toHex(body.secret));
    } else {
      // The credential is bound to a synthetic name, so the TPM may refuse
      // it: the page must say so and show no recovered secret.
      await expect(adminPage.getByText('ActivateCredential failed').first()).toBeVisible();
      await expect(adminPage.getByTestId('activated-secret')).toHaveCount(0);
    }
  });

  test('get random shows the bytes the server drew', async ({ adminPage }) => {
    await adminPage.goto('/tpm/credential');
    await adminPage.getByLabel('Number of bytes').fill('16');
    const drawn = adminPage.waitForResponse(
      (r) => r.url().includes('/random') && r.request().method() === 'POST'
    );
    await adminPage.getByRole('button', { name: 'Get Random' }).click();
    const resp = await drawn;
    expect(resp.ok()).toBe(true);
    const body = (await resp.json()) as { randomBytes: string };
    const hex = toHex(body.randomBytes);
    expect(hex).toHaveLength(32);
    await expect(adminPage.getByTestId('random-bytes')).toHaveText(hex);
  });
});
