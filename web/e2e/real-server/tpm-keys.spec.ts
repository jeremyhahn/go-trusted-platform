import { test, expect } from './fixtures';
import type { Page, Request } from '@playwright/test';
import { daemonApi } from './fixtures/daemon-api';

/**
 * TPM key lifecycle page (#1735, slice 31 of #1665) against the real server.
 *
 * Ported from web/e2e/tpm-keys.spec.ts (#2037). The mocked spec answered
 * every /tpm route through mockTPMKeyOperationsApi. Here the page talks to
 * the harness daemon's TPM. Read-only operations (capabilities, platform
 * attributes, GetAK, quote, verify, certify) run for real and are checked
 * against what the SDK reads back. Operations that would replace or evict
 * the harness's EK, SRK or AK, provision it or clear it are shared by every
 * other TPM spec, so for those the port checks the confirmation dialog and
 * that Cancel sends nothing, and never confirms.
 *
 * Gaps (docs/plans/1665-port-3.md): confirmed provision, clear, create and
 * delete of EK/SRK/AK, EK certificate import with a real certificate, the
 * canned unbound quote and the forced verified:false verdict.
 */

const SRK_HANDLE = 0x81000001;
const MISSING_HANDLE = 0x81fffff0;

/** Records every /tpm request the page sends. */
function recordTpm(page: Page): Request[] {
  const seen: Request[] = [];
  page.on('request', (r) => {
    if (r.url().includes('/tpm/')) seen.push(r);
  });
  return seen;
}

function sent(seen: Request[], method: string, suffix: string): Request | undefined {
  return seen.find((r) => r.method() === method && new URL(r.url()).pathname.endsWith(suffix));
}

async function openKeysPage(page: Page): Promise<Request[]> {
  const seen = recordTpm(page);
  await page.goto('/tpm/keys');
  await expect(page.getByRole('heading', { name: /tpm keys/i })).toBeVisible();
  return seen;
}

/** Opens a destructive operation's dialog, cancels it and checks nothing was sent. */
async function cancelDestructive(
  page: Page,
  seen: Request[],
  op: string,
  method: string,
  suffix: string,
): Promise<void> {
  await page.getByTestId(`tpm-op-${op}`).click();
  await expect(page.getByTestId('tpm-confirm-dialog')).toBeVisible();
  await expect(page.getByTestId('tpm-confirm-ok')).toBeVisible();
  await page.getByTestId('tpm-confirm-cancel').click();
  await expect(page.getByTestId('tpm-confirm-dialog')).toBeHidden();
  expect(sent(seen, method, suffix)).toBeUndefined();
}

/** Waits for the operation's result or error panel and returns which one showed. */
async function outcome(page: Page, op: string): Promise<'result' | 'error'> {
  const result = page.getByTestId(`tpm-result-${op}`);
  const error = page.getByTestId(`tpm-error-${op}`);
  await expect(result.or(error)).toBeVisible();
  return (await result.isVisible()) ? 'result' : 'error';
}

test.describe('TPM Keys operations (real server)', () => {
  test('Clear asks for confirmation; Cancel sends nothing', async ({ adminPage }) => {
    const seen = await openKeysPage(adminPage);
    await adminPage.getByLabel('Owner password').fill('owner-secret');
    await cancelDestructive(adminPage, seen, 'clear', 'POST', '/tpm/clear');
  });

  test('DeleteEK, DeleteSRK and DeleteAK ask for confirmation; Cancel sends nothing', async ({
    adminPage,
  }) => {
    const seen = await openKeysPage(adminPage);
    await cancelDestructive(adminPage, seen, 'deleteEK', 'DELETE', '');
    await cancelDestructive(adminPage, seen, 'deleteSRK', 'DELETE', '');
    await cancelDestructive(adminPage, seen, 'deleteAK', 'DELETE', '');
    expect(seen.filter((r) => r.method() === 'DELETE')).toHaveLength(0);
  });

  test('Provision, CreateEK, CreateSRK and CreateAK are offered', async ({ adminPage }) => {
    const seen = await openKeysPage(adminPage);
    for (const op of ['provision', 'createEK', 'createSRK', 'createAK']) {
      await expect(adminPage.getByTestId(`tpm-op-${op}`)).toBeVisible();
    }
    expect(seen.filter((r) => r.method() === 'POST')).toHaveLength(0);
  });

  test('GetCapabilities shows /tpm/capabilities', async ({ adminPage }) => {
    const res = await daemonApi(adminPage).getTPMCapabilities();
    expect(res.success).toBe(true);

    await openKeysPage(adminPage);
    const reply = adminPage.waitForResponse(
      (r) => r.url().includes('/tpm/capabilities') && r.request().method() === 'GET',
    );
    await adminPage.getByTestId('tpm-op-capabilities').click();
    expect((await reply).ok()).toBe(true);
    await expect(adminPage.getByTestId('tpm-result-capabilities')).not.toBeEmpty();
  });

  test('GetPlatformAttributes shows /tpm/platform', async ({ adminPage }) => {
    const res = await daemonApi(adminPage).getTPMPlatformAttributes();
    expect(res.success).toBe(true);
    const manufacturer = (res.data as { manufacturer?: unknown } | undefined)?.manufacturer;

    await openKeysPage(adminPage);
    await adminPage.getByTestId('tpm-op-platform').click();
    const panel = adminPage.getByTestId('tpm-result-platform');
    await expect(panel).toBeVisible();
    if (typeof manufacturer === 'string' && manufacturer) {
      await expect(panel).toContainText(manufacturer);
    }
  });

  test('ImportEKCertificate is disabled until a certificate is entered and sends DER', async ({
    adminPage,
  }) => {
    await openKeysPage(adminPage);
    await expect(adminPage.getByTestId('tpm-op-importEKCertificate')).toBeDisabled();

    const pem = '-----BEGIN CERTIFICATE-----\nTUlJQg==\n-----END CERTIFICATE-----';
    await adminPage.getByLabel('EK certificate (PEM)').fill(pem);
    const post = adminPage.waitForRequest(
      (r) => r.url().includes('/tpm/ek/certificate') && r.method() === 'POST',
    );
    await adminPage.getByTestId('tpm-op-importEKCertificate').click();
    // The server stores DER only: the PEM body (base64 DER) is sent as DER.
    expect((await post).postDataJSON()).toMatchObject({ format: 'DER', certificate: 'TUlJQg==' });
    // Not a parseable certificate: the server refuses it.
    expect(await outcome(adminPage, 'importEKCertificate')).toBe('error');
  });

  test('GetAK shows /tpm/ak', async ({ adminPage, sdk }) => {
    const res = await sdk.tpm.getAK();
    await openKeysPage(adminPage);
    await adminPage.getByTestId('tpm-op-getAK').click();
    const shown = await outcome(adminPage, 'getAK');
    expect(shown).toBe(res.success ? 'result' : 'error');
    const handle = (res.data as { handle?: unknown } | undefined)?.handle;
    if (res.success && typeof handle === 'number') {
      await expect(adminPage.getByTestId('tpm-result-getAK')).toContainText(String(handle));
    }
  });

  test('Quote posts to /tpm/quote and VerifyQuote verifies it', async ({ adminPage }) => {
    await openKeysPage(adminPage);
    await expect(adminPage.getByTestId('tpm-op-verifyQuote')).toBeDisabled();
    await adminPage.getByLabel('PCRs to quote').fill('0, 7');
    const quote = adminPage.waitForResponse(
      (r) => r.url().includes('/tpm/quote') && !r.url().includes('/verify') && r.request().method() === 'POST',
    );
    await adminPage.getByTestId('tpm-op-quote').click();
    const quoteReply = await quote;
    const body = quoteReply.request().postDataJSON() as {
      pcrIndices: number[];
      pcrBank: string;
      nonce?: string;
    };
    expect(body).toMatchObject({ pcrIndices: [0, 7], pcrBank: 'PCR_BANK_SHA256' });
    expect(body.nonce).toBeTruthy();

    if (!quoteReply.ok()) {
      await expect(adminPage.getByTestId('tpm-error-quote')).toBeVisible();
      await expect(adminPage.getByTestId('tpm-op-verifyQuote')).toBeDisabled();
      return;
    }
    if ((await outcome(adminPage, 'quote')) === 'error') {
      // The page refused the answer (unbound): verify stays disabled.
      await expect(adminPage.getByTestId('tpm-op-verifyQuote')).toBeDisabled();
      return;
    }

    await expect(adminPage.getByTestId('tpm-op-verifyQuote')).toBeEnabled();
    const verify = adminPage.waitForRequest(
      (r) => r.url().includes('/tpm/quote/verify') && r.method() === 'POST',
    );
    await adminPage.getByTestId('tpm-op-verifyQuote').click();
    const verifyBody = (await verify).postDataJSON() as { nonce?: string; quote?: string };
    expect(verifyBody.nonce).toBe(body.nonce);
    expect(verifyBody.quote).toBeTruthy();
    const verdict = adminPage
      .getByTestId('tpm-result-verifyQuote')
      .or(adminPage.getByTestId('tpm-verdict-verifyQuote'))
      .or(adminPage.getByTestId('tpm-error-verifyQuote'));
    await expect(verdict.first()).toBeVisible();
  });

  test('Quote rejects a malformed PCR list', async ({ adminPage }) => {
    const seen = await openKeysPage(adminPage);
    await adminPage.getByLabel('PCRs to quote').fill('0,7,11x');
    await adminPage.getByTestId('tpm-op-quote').click();

    await expect(adminPage.getByText('Invalid PCR list').first()).toBeVisible();
    expect(sent(seen, 'POST', '/tpm/quote')).toBeUndefined();
    await expect(adminPage.getByTestId('tpm-op-verifyQuote')).toBeDisabled();
  });

  test('Certify posts to /tpm/certify', async ({ adminPage }) => {
    await openKeysPage(adminPage);
    await adminPage.getByLabel('Key handle to certify').fill('0x81000001');
    await adminPage.getByLabel('Key password (optional)').fill('key-secret');
    const post = adminPage.waitForResponse(
      (r) => r.url().includes('/tpm/certify') && r.request().method() === 'POST',
    );
    await adminPage.getByTestId('tpm-op-certify').click();
    const reply = await post;
    expect(reply.request().postDataJSON()).toMatchObject({
      keyHandle: SRK_HANDLE,
      keyPassword: 'key-secret',
    });
    expect(await outcome(adminPage, 'certify')).toBe(reply.ok() ? 'result' : 'error');
  });

  test('a failed operation shows its error', async ({ adminPage }) => {
    await openKeysPage(adminPage);
    await adminPage.getByLabel('Key handle to certify').fill(`0x${MISSING_HANDLE.toString(16)}`);
    const post = adminPage.waitForResponse(
      (r) => r.url().includes('/tpm/certify') && r.request().method() === 'POST',
    );
    await adminPage.getByTestId('tpm-op-certify').click();
    expect((await post).ok()).toBe(false);
    await expect(adminPage.getByTestId('tpm-error-certify')).toBeVisible();
    await expect(adminPage.getByTestId('tpm-result-certify')).toHaveCount(0);
  });
});
