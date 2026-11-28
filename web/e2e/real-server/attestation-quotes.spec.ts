import type { Page, Request, Response } from '@playwright/test';
import type {
  GetAttestationQuoteResponse,
  PlatformClient,
  VerifyAttestationQuoteResponse,
} from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/*
 * The TPM quote card on /attestation/quotes against the real server (#2038,
 * UI epic #1665). The spec compares what the card shows with what the
 * server answered to POST /api/v1/attestation/quote and
 * POST /api/v1/attestation/quote/verify, or, when the server does not offer
 * a route, checks the button is withheld with the server's reason and sends
 * nothing. No page.route mocks.
 */

const QUOTE_OP = 'POST /api/v1/attestation/quote';
const VERIFY_OP = 'POST /api/v1/attestation/quote/verify';
const QUOTE_PATH = '/api/v1/attestation/quote';
const VERIFY_PATH = '/api/v1/attestation/quote/verify';
const NOT_OFFERED = 'not offered by this server';
const NONCE = Buffer.from('real-server quote card nonce').toString('base64');
const JUNK_PEM = '-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----';
const JUNK_QUOTE = {
  quoteData: 'cXVvdGU=',
  signature: 'c2ln',
  signatureAlgorithm: 'SHA256-RSAPSS',
  pcrValues: [],
  nonce: NONCE,
};

interface Capability {
  enabled: boolean;
  reason: string;
}

/** The server's answers for both quote ops from its capabilities list. */
async function quoteCapabilities(sdk: PlatformClient): Promise<Record<string, Capability>> {
  const res = await sdk.capabilities.list();
  if (!res.success || !res.data) {
    throw new Error(`capabilities list failed: ${JSON.stringify(res.error)}`);
  }
  const out: Record<string, Capability> = {};
  for (const op of [QUOTE_OP, VERIFY_OP]) {
    const entry = res.data.capabilities.find((c) => c.op === op);
    out[op] = entry ? { enabled: entry.enabled, reason: entry.reason ?? '' } : { enabled: false, reason: NOT_OFFERED };
  }
  return out;
}

function isPost(r: Request, path: string): boolean {
  return r.method() === 'POST' && new URL(r.url()).pathname === path;
}

function postResponse(page: Page, path: string): Promise<Response> {
  return page.waitForResponse((r) => isPost(r.request(), path));
}

/** The error text of a refused answer, from the control plane's error envelope. */
async function refusalText(r: Response): Promise<string> {
  const body = (await r.json().catch(() => ({}))) as { error?: unknown; message?: unknown };
  if (typeof body.error === 'string') return body.error;
  if (body.error && typeof body.error === 'object' && 'message' in body.error) {
    return String((body.error as { message: unknown }).message);
  }
  return typeof body.message === 'string' ? body.message : '';
}

async function openQuotes(page: Page): Promise<void> {
  await page.goto('/attestation/quotes');
  await expect(page.getByTestId('attestation-quote-card')).toBeVisible();
}

/** Withheld: the button is disabled with the server's reason and a click sends nothing. */
async function expectWithheld(page: Page, name: string, cap: Capability, path: string): Promise<void> {
  const seen: string[] = [];
  page.on('request', (req) => {
    if (isPost(req, path)) seen.push(req.url());
  });
  await openQuotes(page);
  const button = page.getByRole('button', { name });
  await expect(button).toHaveAttribute('data-capability-enabled', 'false');
  await expect(button).toBeDisabled();
  if (cap.reason && cap.reason !== NOT_OFFERED) await expect(button).toHaveAttribute('title', cap.reason);
  await button.click({ force: true });
  expect(seen).toEqual([]);
}

/** Get quote through the card; returns the parsed answer when the server quoted. */
async function getQuote(page: Page): Promise<GetAttestationQuoteResponse | null> {
  await page.getByTestId('attestation-quote-nonce').fill(NONCE);
  await page.getByTestId('attestation-quote-pcrs').fill('0,7');
  const button = page.getByRole('button', { name: 'Get quote' });
  await expect(button).toHaveAttribute('data-capability-enabled', 'true');
  const res = postResponse(page, QUOTE_PATH);
  await button.click();
  const r = await res;

  if (!r.ok()) {
    const text = await refusalText(r);
    await expect(page.getByText(/Quote request failed/).first()).toBeVisible();
    if (text) await expect(page.getByText(text).first()).toBeVisible();
    await expect(page.getByTestId('attestation-quote-result')).toHaveCount(0);
    return null;
  }

  const answer = unwrapPayload<GetAttestationQuoteResponse>(await r.json());
  const result = page.getByTestId('attestation-quote-result');
  await expect(result).toBeVisible();
  if (answer.quote?.signatureAlgorithm) await expect(result).toContainText(answer.quote.signatureAlgorithm);
  if (answer.quote?.nonce) await expect(result).toContainText(answer.quote.nonce);
  await expect(page.getByTestId('attestation-quote-pcr-count')).toHaveText(String(answer.quote?.pcrValues?.length ?? 0));
  if (answer.channelBinding) await expect(result).toContainText(answer.channelBinding);
  return answer;
}

test.describe('TPM quote card (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/quotes');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('Get quote shows what the server answers, or is withheld', async ({ adminPage, sdk }) => {
    const caps = await quoteCapabilities(sdk);
    if (!caps[QUOTE_OP].enabled) {
      await expectWithheld(adminPage, 'Get quote', caps[QUOTE_OP], QUOTE_PATH);
      return;
    }
    await openQuotes(adminPage);
    await getQuote(adminPage);
  });

  test('Verify quote shows the verdict against a junk AK key, or is withheld', async ({ adminPage, sdk }) => {
    const caps = await quoteCapabilities(sdk);
    if (!caps[VERIFY_OP].enabled) {
      await expectWithheld(adminPage, 'Verify quote', caps[VERIFY_OP], VERIFY_PATH);
      return;
    }
    await openQuotes(adminPage);

    // Verify the quote the Get quote flow produced when the server quotes;
    // otherwise a hand-made quote over the same nonce.
    const quoted = caps[QUOTE_OP].enabled ? await getQuote(adminPage) : null;
    if (!quoted?.quote) {
      await adminPage.getByTestId('attestation-verify-quote').fill(JSON.stringify(JUNK_QUOTE));
    }
    await adminPage.getByTestId('attestation-verify-ak-pem').fill(JUNK_PEM);
    await adminPage.getByTestId('attestation-verify-nonce').fill(NONCE);

    const button = adminPage.getByRole('button', { name: 'Verify quote' });
    await expect(button).toHaveAttribute('data-capability-enabled', 'true');
    const res = postResponse(adminPage, VERIFY_PATH);
    await button.click();
    const r = await res;

    if (!r.ok()) {
      const text = await refusalText(r);
      await expect(adminPage.getByText(/Quote verification failed/).first()).toBeVisible();
      if (text) await expect(adminPage.getByText(text).first()).toBeVisible();
      await expect(adminPage.getByTestId('attestation-quote-verdict')).toHaveCount(0);
      return;
    }

    const answer = unwrapPayload<VerifyAttestationQuoteResponse>(await r.json());
    // A junk AK key never verifies a quote.
    expect(answer.verified).toBe(false);
    const verdict = adminPage.getByTestId('attestation-quote-verdict');
    await expect(verdict).toContainText('not verified');
    if (answer.message) await expect(verdict).toContainText(answer.message);
  });
});
