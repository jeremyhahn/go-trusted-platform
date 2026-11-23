import type { Page, Request, Response } from '@playwright/test';
import type { PlatformClient, PollDeviceVerdictsResponse } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/*
 * The device verdicts page (/attestation/verdicts) against the real server
 * (#2038, UI epic #1665). The spec compares what the page shows with what
 * the server answered: the verdicts polled from GET /api/v1/attestation/verdicts,
 * the error card when the server refuses the poll (it answers 503 when it has
 * no verdict poller), or, when the server does not offer that route, the
 * not-enabled card with the server's reason. No page.route mocks.
 */

const OP = 'GET /api/v1/attestation/verdicts';
const VERDICTS_PATH = '/api/v1/attestation/verdicts';
const NOT_OFFERED = 'not offered by this server';

interface VerdictsCapability {
  enabled: boolean;
  reason: string;
}

/** The server's answer for OP from its capabilities list. */
async function verdictsCapability(sdk: PlatformClient): Promise<VerdictsCapability> {
  const res = await sdk.capabilities.list();
  if (!res.success || !res.data) {
    throw new Error(`capabilities list failed: ${JSON.stringify(res.error)}`);
  }
  const entry = res.data.capabilities.find((c) => c.op === OP);
  if (!entry) return { enabled: false, reason: NOT_OFFERED };
  return { enabled: entry.enabled, reason: entry.reason ?? '' };
}

/** A GET of the verdicts route, with any query. */
function isVerdictsGet(r: Request): boolean {
  return r.method() === 'GET' && new URL(r.url()).pathname === VERDICTS_PATH;
}

function verdictsResponse(page: Page): Promise<Response> {
  return page.waitForResponse((r) => isVerdictsGet(r.request()));
}

test.describe('Device verdicts (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/verdicts');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('shows the polled verdicts, the server refusal, or the not-enabled card', async ({ adminPage, sdk }) => {
    const cap = await verdictsCapability(sdk);

    if (cap.enabled) {
      const res = verdictsResponse(adminPage);
      await adminPage.goto('/attestation/verdicts');
      const r = await res;
      if (!r.ok()) {
        await expect(adminPage.getByTestId('verdicts-error')).toBeVisible();
        await expect(adminPage.getByTestId('verdicts-table')).toHaveCount(0);
        return;
      }
      const answer = unwrapPayload<PollDeviceVerdictsResponse>(await r.json());

      const table = adminPage.getByTestId('verdicts-table');
      await expect(table).toBeVisible();
      const verdicts = answer.verdicts ?? [];
      if (verdicts.length === 0) {
        await expect(table).toContainText('No verdicts yet');
        return;
      }
      for (const v of verdicts) {
        const row = adminPage.getByTestId(`verdict-${v.eventId}`);
        await expect(row).toHaveCount(1);
        await expect(row).toContainText(v.serial);
      }
      return;
    }

    const seen: string[] = [];
    adminPage.on('request', (req) => {
      if (isVerdictsGet(req)) seen.push(req.url());
    });
    await adminPage.goto('/attestation/verdicts');
    const notEnabled = adminPage.getByTestId('verdicts-not-enabled');
    await expect(notEnabled).toBeVisible();
    if (cap.reason) await expect(notEnabled).toContainText(cap.reason);
    await expect(adminPage.getByTestId('verdicts-table')).toHaveCount(0);
    expect(seen).toEqual([]);
  });

  test('Check for new verdicts continues from the cursor', async ({ adminPage, sdk }) => {
    const cap = await verdictsCapability(sdk);
    if (cap.enabled) {
      const first = verdictsResponse(adminPage);
      await adminPage.goto('/attestation/verdicts');
      const r = await first;
      if (!r.ok()) {
        await expect(adminPage.getByTestId('verdicts-error')).toBeVisible();
        return;
      }
      const answer = unwrapPayload<PollDeviceVerdictsResponse>(await r.json());
      await expect(adminPage.getByTestId('verdicts-table')).toBeVisible();

      const next = adminPage.waitForRequest(isVerdictsGet);
      await adminPage.getByRole('button', { name: 'Check for new verdicts' }).click();
      const url = new URL((await next).url());
      // The SDK leaves an empty cursor out of the query.
      expect(url.searchParams.get('cursor') ?? '').toBe(answer.cursor ?? '');
      expect(url.searchParams.get('wait_ms')).toBe('0');
    }
  });
});
