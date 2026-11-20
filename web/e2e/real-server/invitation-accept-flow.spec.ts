/**
 * Invitation detail, lookup by token and accept flow against the real-server
 * harness (#2036, epic #1665).
 *
 * Ported from web/e2e/invitation-accept-flow.spec.ts. Each test creates its
 * own invitation through sdk.invitation.create (a unique email), drives the
 * page with the id and token the server returned, and revokes it afterwards.
 * The public invite page is opened in a fresh context with no session.
 *
 * Operations:
 * - GetInvitation         GET  /invitations/{id}
 * - GetInvitationByToken  GET  /invitations/token/{token}
 * - AcceptInvitation      POST /invitations/accept
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

function uniqueEmail(tag: string): string {
  return `inv-${tag}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 6)}@example.com`;
}

async function createInvitation(sdk: PlatformClient, tag: string, role: string): Promise<Created> {
  const email = uniqueEmail(tag);
  const res = await sdk.invitation.create({ email, role });
  const err: unknown = res.error;
  if (!res.success || !res.data) throw new Error(`[real-server] invitation.create: ${JSON.stringify(err)}`);
  const inv = res.data.invitation;
  return { id: inv.id, token: inv.token, email };
}

/** A page with no session, as the invitee who follows the link. */
async function anonymousPage(browser: Browser, baseURL: string | undefined): Promise<Page> {
  const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
  return context.newPage();
}

test.describe('Invitation accept flow', () => {
  test('GetInvitation: invitation detail page shows the invitation', async ({ adminPage, sdk }) => {
    const inv = await createInvitation(sdk, 'detail', 'admin');
    try {
      await adminPage.goto('/admin/invitations');
      await adminPage.getByTestId(`view-invitation-${inv.id}`).click();

      await expect(adminPage).toHaveURL(new RegExp(`/admin/invitations/detail/?\\?id=${inv.id}`));
      await expect(adminPage.getByTestId('invitation-detail-id')).toHaveText(inv.id);
      await expect(adminPage.getByTestId('invitation-detail-email')).toHaveText(inv.email);
      await expect(adminPage.getByTestId('invitation-detail-role')).toHaveText('admin');
      await expect(adminPage.getByTestId('invitation-detail-status')).toHaveText('pending');
    } finally {
      await sdk.invitation.revoke(inv.id);
    }
  });

  test('GetInvitation: unknown id shows the error', async ({ adminPage, sdk }) => {
    const missing = `missing-${Date.now().toString(36)}`;
    const res = await sdk.invitation.get(missing);
    expect(res.success).toBe(false);

    await adminPage.goto(`/admin/invitations/detail/?id=${missing}`);
    await expect(adminPage.getByTestId('invitation-detail-error')).toContainText('Invitation not found');
  });

  test('GetInvitationByToken: public invite page looks the invitation up by token', async ({
    browser,
    baseURL,
    sdk,
    tenant,
  }) => {
    const inv = await createInvitation(sdk, 'tok', 'member');
    const page = await anonymousPage(browser, baseURL);
    try {
      await page.goto(`/invite/?token=${encodeURIComponent(inv.token)}`);

      await expect(page.getByTestId('invite-email')).toHaveText(inv.email);
      await expect(page.getByTestId('invite-role')).toHaveText('member');
      await expect(page.getByTestId('invite-tenant')).toHaveText(tenant.name);
      await expect(page.getByTestId('invite-join')).toHaveAttribute(
        'href',
        `/auth/webauthn/?invitation=${encodeURIComponent(inv.token)}&tenant_name=${encodeURIComponent(tenant.name)}`,
      );
    } finally {
      await page.context().close();
      await sdk.invitation.revoke(inv.id);
    }
  });

  test('GetInvitationByToken: an unknown token shows the error and no join link', async ({ browser, baseURL }) => {
    const page = await anonymousPage(browser, baseURL);
    try {
      await page.goto(`/invite/?token=nope-${Date.now().toString(36)}`);

      await expect(page.getByTestId('invite-error')).toContainText('Invalid or expired invitation');
      await expect(page.getByTestId('invite-join')).toHaveCount(0);
    } finally {
      await page.context().close();
    }
  });

  test('AcceptInvitation: the join link is the registration flow and posts nothing to /invitations/accept', async ({
    browser,
    baseURL,
    sdk,
  }) => {
    const inv = await createInvitation(sdk, 'join', 'member');
    const page = await anonymousPage(browser, baseURL);
    const accepts: string[] = [];
    page.on('request', (req) => {
      if (req.method() === 'POST' && /\/invitations\/accept\b/.test(req.url())) accepts.push(req.url());
    });
    try {
      await page.goto(`/invite/?token=${encodeURIComponent(inv.token)}`);

      const join = page.getByTestId('invite-join');
      await expect(join).toHaveAttribute('href', new RegExp(`^/auth/webauthn/\\?invitation=${escapeRe(encodeURIComponent(inv.token))}`));
      await join.click();

      // The registration flow (BeginRegistration with invitation_token) joins
      // the invitee and consumes the invitation; the invite page never calls
      // AcceptInvitation itself.
      await expect(page).toHaveURL(new RegExp(`/auth/webauthn/\\?invitation=${escapeRe(encodeURIComponent(inv.token))}`));
      expect(accepts).toHaveLength(0);
      // The invitation is still pending on the server.
      const after = await sdk.invitation.get(inv.id);
      expect(after.data?.invitation.status).toBe('pending');
    } finally {
      await page.context().close();
      await sdk.invitation.revoke(inv.id);
    }
  });
});
