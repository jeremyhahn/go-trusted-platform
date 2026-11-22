/**
 * NTP page against the real-server harness (#2058, ruling 972).
 *
 * No page.route and no api-mock: the test registers a passkey through the
 * virtual authenticator, so the session is a server-issued JWT, then reads
 * GET /api/v1/capabilities and the NTP routes from the running server. The
 * clock is never stepped: the confirm dialog is opened and cancelled.
 */

import type { Page } from '@playwright/test';
import { test, expect } from './fixtures/auth.fixture';

interface Capability {
  op: string;
  kind?: string;
  enabled: boolean;
  reason?: string;
}

function uniqueUsername(prefix = 'e2e'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

/** Navigate to WebAuthn page and switch to registration mode. */
async function goToRegistration(page: Page) {
  await page.goto('/auth/webauthn', { waitUntil: 'networkidle' });

  const registerLink = page.getByText(/don.*have an account.*register/i);
  if (await registerLink.isVisible({ timeout: 3000 }).catch(() => false)) {
    await registerLink.click();
    await expect(page.getByRole('button', { name: /register|create account/i })).toBeVisible();
  }
}

/** Assert auth succeeded — JWT cookie present and no longer on auth page. */
async function assertAuthSuccess(page: Page) {
  await page.waitForFunction(() => {
    return !window.location.pathname.includes('/auth/webauthn') ||
      document.body.innerText.includes('Dashboard') ||
      document.body.innerText.includes('Protected') ||
      document.body.innerText.includes('Log Out') ||
      document.body.innerText.includes('Overview');
  }, { timeout: 15_000 });

  const cookies = await page.context().cookies();
  const jwtCookie = cookies.find((c) => c.name === 'jwt');
  expect(jwtCookie).toBeDefined();
  expect(jwtCookie!.value.length).toBeGreaterThan(0);
}

function isGet(path: string) {
  return (r: import('@playwright/test').Response) =>
    new URL(r.url()).pathname === path && r.request().method() === 'GET';
}

test.describe('NTP page', () => {
  test('shows the status card or the not-enabled card, with Step Clock gated', async ({
    page,
    setupVirtualAuthenticator,
    cleanupVirtualAuthenticator,
  }) => {
    await goToRegistration(page);
    const { cdpSession, authenticatorId } = await setupVirtualAuthenticator(page);

    try {
      await page.getByPlaceholder(/enter your username/i).fill(uniqueUsername('ntp'));
      const registrationFinish = page.waitForResponse(
        (resp) =>
          resp.url().includes('/api/v1/webauthn/registration/finish') &&
          resp.status() === 200
      );
      await page.getByRole('button', { name: /register|create account/i }).click();
      await registrationFinish;
      await assertAuthSuccess(page);

      const capsResponse = page.waitForResponse(isGet('/api/v1/capabilities'));
      const statusResponse = page
        .waitForResponse(isGet('/api/v1/ntp/status'), { timeout: 15_000 })
        .catch(() => null);
      await page.goto('/networking/ntp');

      const resp = await capsResponse;
      expect(resp.status()).toBe(200);
      const body = await resp.json();
      const list: Capability[] = body?.payload?.capabilities ?? body?.capabilities ?? [];
      expect(list.length).toBeGreaterThan(0);

      const enabled = (op: string) => list.find((c) => c.op === op)?.enabled === true;
      const statusEnabled = enabled('GET /api/v1/ntp/status');
      const stepEnabled = enabled('POST /api/v1/ntp/step');

      const statusCard = page.locator('[data-testid="ntp-status-card"]');
      const notEnabled = page.locator('[data-testid="ntp-not-enabled"]');
      if (statusEnabled) {
        const status = await statusResponse;
        expect(status, 'GET /api/v1/ntp/status was not read').not.toBeNull();
        expect(status!.status()).toBe(200);
        await expect(statusCard).toBeVisible();
        await expect(notEnabled).toHaveCount(0);
      } else {
        await expect(notEnabled).toBeVisible();
      }

      const step = page.getByRole('button', { name: 'Step Clock' });
      await expect(step).toHaveAttribute('data-capability-op', 'POST /api/v1/ntp/step');
      await expect(step).toHaveAttribute('data-capability-enabled', String(stepEnabled));

      if (stepEnabled) {
        await step.click();
        await expect(page.getByRole('dialog')).toBeVisible();
        await page.getByRole('button', { name: 'Cancel' }).click();
        await expect(page.getByRole('dialog')).toBeHidden();
      }
    } finally {
      await cleanupVirtualAuthenticator(cdpSession, authenticatorId);
    }
  });
});
