import type { Page, Request, Response } from '@playwright/test';
import type { CallerPolicyDescription, PlatformClient } from 'trusted-platform-sdk';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/*
 * The caller policy page (/attestation/callers) against the real server
 * (#2038, UI epic #1665). The spec compares what the page shows with what
 * the server answered: the policy read from GET /api/v1/attestation/callers,
 * or, when the server does not offer that route, the not-enabled card with
 * the server's reason. No page.route mocks.
 */

const OP = 'GET /api/v1/attestation/callers';
const CALLERS_PATH = '/api/v1/attestation/callers';
const NOT_OFFERED = 'not offered by this server';

interface CallerCapability {
  enabled: boolean;
  reason: string;
}

/** The server's answer for OP from its capabilities list. */
async function callerCapability(sdk: PlatformClient): Promise<CallerCapability> {
  const res = await sdk.capabilities.list();
  if (!res.success || !res.data) {
    throw new Error(`capabilities list failed: ${JSON.stringify(res.error)}`);
  }
  const entry = res.data.capabilities.find((c) => c.op === OP);
  if (!entry) return { enabled: false, reason: NOT_OFFERED };
  return { enabled: entry.enabled, reason: entry.reason ?? '' };
}

function isCallersGet(r: Request): boolean {
  return r.method() === 'GET' && new URL(r.url()).pathname === CALLERS_PATH;
}

function callersResponse(page: Page): Promise<Response> {
  return page.waitForResponse((r) => isCallersGet(r.request()));
}

test.describe('Caller policy (real server)', () => {
  test('redirects to login when not authenticated', async ({ page }) => {
    await page.goto('/attestation/callers');
    await expect(page).toHaveURL(/\/auth\/webauthn/);
  });

  test('shows the policy the server answers, or the not-enabled card', async ({ adminPage, sdk }) => {
    const cap = await callerCapability(sdk);

    if (cap.enabled) {
      const res = callersResponse(adminPage);
      await adminPage.goto('/attestation/callers');
      const r = await res;
      expect(r.ok()).toBeTruthy();
      const policy = unwrapPayload<CallerPolicyDescription>(await r.json());

      const card = adminPage.getByTestId('caller-policy');
      await expect(card).toBeVisible();
      await expect(card).toContainText(policy.strategy);
      for (const id of policy.identities ?? []) {
        await expect(card).toContainText(id);
      }
      await expect(adminPage.getByTestId('caller-admits-nobody')).toHaveCount(policy.admits_nobody ? 1 : 0);
      if (policy.admits_nobody) {
        await expect(adminPage.getByTestId('caller-admits-nobody')).toBeVisible();
      }
      return;
    }

    const seen: string[] = [];
    adminPage.on('request', (req) => {
      if (isCallersGet(req)) seen.push(req.url());
    });
    await adminPage.goto('/attestation/callers');
    const notEnabled = adminPage.getByTestId('caller-policy-not-enabled');
    await expect(notEnabled).toBeVisible();
    if (cap.reason) await expect(notEnabled).toContainText(cap.reason);
    await expect(adminPage.getByTestId('caller-policy')).toHaveCount(0);
    expect(seen).toEqual([]);
  });

  test('Refresh re-reads the policy when offered', async ({ adminPage, sdk }) => {
    const cap = await callerCapability(sdk);
    test.skip(!cap.enabled, `${OP} not offered`);

    const first = callersResponse(adminPage);
    await adminPage.goto('/attestation/callers');
    expect((await first).ok()).toBeTruthy();
    await expect(adminPage.getByTestId('caller-policy')).toBeVisible();

    const again = callersResponse(adminPage);
    await adminPage.getByRole('button', { name: /refresh/i }).click();
    expect((await again).ok()).toBeTruthy();
  });
});
