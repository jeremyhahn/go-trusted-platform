import type { Locator, Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';
import { unwrapPayload } from './fixtures/wire';

/**
 * Bootstrap ceremony page against the real platformd (#2042, epic #1665).
 *
 * No mocked routes: every assertion compares the page with what the server
 * answered the page's own request. The harness does not say whether the
 * daemon mounts a CeremonyService, so the status test asserts both the
 * answered and the refused branch, and never assumes a ceremony state.
 *
 * Not covered here:
 *   - Init: it changes the shared daemon's ceremony state for every worker;
 *     it needs a disposable daemon of its own.
 *   - A completed claim or a signed CSR: they need an enrolled officer and
 *     key material the harness does not seed.
 */

/** Waits for the page's own request with this method and path, and returns its response. */
function apiResponse(page: Page, method: string, path: string): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === method && new URL(r.url()).pathname === path,
  );
}

/** The card whose title is exactly `title`. */
function card(page: Page, title: string): Locator {
  return page.locator('div.bg-card').filter({ has: page.getByText(title, { exact: true }) });
}

/** The `dd` that follows the `dt` reading `term` inside `scope`. */
function definition(scope: Locator, term: string): Locator {
  return scope.locator(`dt:text-is("${term}") + dd`);
}

/** The ceremony status fields the card shows. */
interface WireCeremonyStatus {
  ceremonyId?: string;
  threshold?: number | string;
}

const placeholderCsr = [
  '-----BEGIN CERTIFICATE REQUEST-----',
  'TEST',
  '-----END CERTIFICATE REQUEST-----',
].join('\n');

test.describe('Bootstrap ceremony against the real platformd', () => {
  test('the sidebar links the ceremony page', async ({ adminPage }) => {
    await adminPage.goto('/dashboard');
    // The Platform group starts collapsed off its own pages; open it first.
    await adminPage.getByRole('button', { name: 'Platform', exact: true }).click();
    await adminPage.getByRole('link', { name: 'Bootstrap Ceremony' }).click();
    await expect(adminPage).toHaveURL(/\/platform\/ceremony$/);
    await expect(adminPage.getByRole('heading', { name: 'Bootstrap ceremony' })).toBeVisible();
  });

  test('the status card shows what the server answered', async ({ adminPage }) => {
    const answered = apiResponse(adminPage, 'GET', '/api/v1/ceremony/status');
    await adminPage.goto('/platform/ceremony');
    const r = await answered;
    const status = card(adminPage, 'Ceremony status');

    if (r.ok()) {
      const payload = unwrapPayload<WireCeremonyStatus>(await r.json());
      await expect(definition(status, 'Ceremony ID')).toHaveText(payload.ceremonyId || '-');
      await expect(definition(status, 'Threshold')).toHaveText(
        // The card's UNAVAILABLE (ceremony-status-card.tsx) for an unreported threshold.
        payload.threshold ? String(payload.threshold) : 'Unavailable',
      );
      const state = definition(status, 'State');
      await expect(state).toBeVisible();
      await expect(state).not.toHaveText('');
      await expect(status.getByRole('alert')).toHaveCount(0);
    } else {
      await expect(status.getByRole('alert')).toContainText('Ceremony status unavailable:');
    }
  });

  test('a claim-cert request for an unknown officer is refused by the server', async ({
    adminPage,
  }) => {
    await adminPage.goto('/platform/ceremony');
    const claim = card(adminPage, 'Claim officer certificate');
    await claim.locator('#claim-cert-username').fill('nobody@example.com');

    const answered = apiResponse(adminPage, 'POST', '/api/v1/ceremony/claim-cert/begin');
    await claim.getByRole('button', { name: 'Request challenge' }).click();
    const r = await answered;

    expect(r.ok(), `claim-cert begin answered ${r.status()}`).toBeFalsy();
    await expect(claim.getByRole('alert')).toContainText('Claim refused:');
  });

  test('a claim-share request for an unknown officer is refused by the server', async ({
    adminPage,
  }) => {
    await adminPage.goto('/platform/ceremony');
    const claim = card(adminPage, 'Claim key share');
    await claim.locator('#claim-share-username').fill('nobody@example.com');

    const answered = apiResponse(adminPage, 'POST', '/api/v1/ceremony/claim-share/begin');
    await claim.getByRole('button', { name: 'Request challenge' }).click();
    const r = await answered;

    expect(r.ok(), `claim-share begin answered ${r.status()}`).toBeFalsy();
    await expect(claim.getByRole('alert')).toContainText('Claim share refused:');
  });

  test('Sign CSR with a malformed CSR is refused by the server', async ({ adminPage }) => {
    await adminPage.goto('/platform/ceremony');
    const sign = card(adminPage, 'Sign officer CSR');
    await sign.locator('#ceremony-sign-username').fill('nobody@example.com');
    await sign.locator('#ceremony-sign-so-pin').fill('00000000');
    await sign.locator('#ceremony-sign-csr').fill(placeholderCsr);

    const answered = apiResponse(adminPage, 'POST', '/api/v1/ceremony/sign-csr');
    await sign.getByRole('button', { name: 'Sign CSR' }).click();
    const r = await answered;

    expect(r.ok(), `sign-csr answered ${r.status()}`).toBeFalsy();
    await expect(sign.getByRole('alert')).toContainText('Sign CSR refused:');
  });
});
