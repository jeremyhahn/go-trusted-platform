/**
 * Invitation lookup and accept pages against the real-server harness
 * (#2036, epic #1665; slice 19 of #1665, #1671).
 *
 * Ported from web/e2e/invitation-accept.spec.ts. Each test creates its own
 * invitation through sdk.invitation.create (a unique email) and opens the
 * pages with the id and token the server returned; the invitation is revoked
 * afterwards. A signed-out visitor is a fresh context with no session.
 */
import { test, expect } from './fixtures';
import type { Browser, Page } from '@playwright/test';
import type { PlatformClient } from 'trusted-platform-sdk';

interface Created {
  id: string;
  token: string;
  email: string;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function createInvitation(sdk: PlatformClient, tag: string, role = 'admin'): Promise<Created> {
  const email = `inv-${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}@example.com`;
  const res = await sdk.invitation.create({ email, role });
  const err: unknown = res.error;
  if (!res.success || !res.data) throw new Error(`[real-server] invitation.create: ${JSON.stringify(err)}`);
  return { id: res.data.invitation.id, token: res.data.invitation.token, email };
}

async function anonymousPage(browser: Browser, baseURL: string | undefined): Promise<Page> {
  const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
  return context.newPage();
}

/** Records the POSTs page sends to /invitations/accept. */
function recordAccepts(page: Page): string[] {
  const accepts: string[] = [];
  page.on('request', (req) => {
    if (req.method() === 'POST' && /\/invitations\/accept\b/.test(req.url())) accepts.push(req.url());
  });
  return accepts;
}

test.describe('Invitation lookup and accept', () => {
  test('GetInvitation: detail page shows an invitation by id', async ({ adminPage, sdk }) => {
    const inv = await createInvitation(sdk, 'detail');
    try {
      const lookup = adminPage.waitForRequest(
        (req) =>
          req.method() === 'GET' &&
          new RegExp(`/api/v1/invitations/${escapeRe(encodeURIComponent(inv.id))}/?(\\?|$)`).test(req.url()),
      );
      await adminPage.goto(`/tenant/invitations/${encodeURIComponent(inv.id)}`);
      await lookup;

      await expect(adminPage.getByRole('heading', { name: 'Invitation Details' })).toBeVisible();
      await expect(adminPage.getByText(inv.email).first()).toBeVisible();
      await expect(adminPage.getByTestId('invitation-status')).toHaveText('Pending');
    } finally {
      await sdk.invitation.revoke(inv.id);
    }
  });

  test('GetInvitation: unknown id shows an error', async ({ adminPage }) => {
    await adminPage.goto(`/tenant/invitations/inv-missing-${Date.now().toString(36)}`);
    await expect(adminPage.getByText('Error loading invitation')).toBeVisible();
  });

  test('GetInvitationByToken: invite page shows the invitation for a token', async ({ browser, baseURL, sdk }) => {
    const inv = await createInvitation(sdk, 'tok');
    const page = await anonymousPage(browser, baseURL);
    try {
      const token = encodeURIComponent(inv.token);
      const lookup = page.waitForRequest((req) =>
        new RegExp(`/api/v1/invitations/token/${escapeRe(token)}/?(\\?|$)`).test(req.url()),
      );
      await page.goto(`/invite/${token}`);
      await lookup;

      await expect(page.getByText('You have been invited')).toBeVisible();
      await expect(page.getByText(new RegExp(`${escapeRe(inv.email)} is invited`))).toBeVisible();
      const signUp = page.getByRole('link', { name: 'Create account with passkey' });
      await expect(signUp).toBeVisible();
      await expect(signUp).toHaveAttribute('href', new RegExp(`/auth/webauthn\\?invitation=${escapeRe(token)}`));
      await expect(page.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
    } finally {
      await page.context().close();
      await sdk.invitation.revoke(inv.id);
    }
  });

  test('GetInvitationByToken: unknown token shows an invalid invitation', async ({ browser, baseURL }) => {
    const page = await anonymousPage(browser, baseURL);
    try {
      await page.goto(`/invite/tok-unknown-${Date.now().toString(36)}`);
      await expect(page.getByText('Invalid invitation')).toBeVisible();
    } finally {
      await page.context().close();
    }
  });

  // Codex round 2 (#1681): AcceptInvitation only marks the invitation accepted
  // and never joins the user to the tenant, so the page must not call it.
  test('AcceptInvitation: a signed-in session sends no accept', async ({ adminPage, sdk }) => {
    const inv = await createInvitation(sdk, 'signed-in');
    try {
      const accepts = recordAccepts(adminPage);
      await adminPage.goto(`/invite/${encodeURIComponent(inv.token)}`);
      await expect(adminPage.getByRole('status').first()).toBeVisible();
      await expect(adminPage.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
      expect(accepts).toEqual([]);
      const after = await sdk.invitation.get(inv.id);
      expect(after.data?.invitation.status).toBe('pending');
    } finally {
      await sdk.invitation.revoke(inv.id);
    }
  });

  test('AcceptInvitation: a signed-out visitor gets the passkey sign-up link', async ({ browser, baseURL, sdk }) => {
    const inv = await createInvitation(sdk, 'signed-out');
    const page = await anonymousPage(browser, baseURL);
    try {
      const accepts = recordAccepts(page);
      await page.goto(`/invite/${encodeURIComponent(inv.token)}`);
      await expect(page.getByRole('link', { name: 'Create account with passkey' })).toBeVisible();
      expect(accepts).toEqual([]);
    } finally {
      await page.context().close();
      await sdk.invitation.revoke(inv.id);
    }
  });
});
