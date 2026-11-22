import type { Page, Response } from '@playwright/test';
import { expect, test } from './fixtures';

/**
 * Invitation detail and invitation link against the real platformd
 * (#2056, epic #1665).
 *
 * The invitation is seeded through the SDK; the page reads it back through
 * its own calls (GetInvitation behind the capability gate on the tenant
 * invitations page, GetInvitationByToken on the passkey page). No page.route.
 */

/** Waits for the page's own GET whose path matches. */
function apiResponse(page: Page, path: RegExp): Promise<Response> {
  return page.waitForResponse(
    (r) => r.request().method() === 'GET' && path.test(new URL(r.url()).pathname),
  );
}

/** The token an invitation link carries: the reply's token, else its inviteUrl's query. */
function invitationToken(invitation: { token?: string; inviteUrl?: string }, baseURL: string): string | undefined {
  if (invitation.token) return invitation.token;
  if (!invitation.inviteUrl) return undefined;
  return new URL(invitation.inviteUrl, baseURL).searchParams.get('invitation') ?? undefined;
}

function uniqueEmail(label: string): string {
  return `e2e-invite-${label}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}@example.com`;
}

test.describe('Invitation detail', () => {
  test('View details shows the invitation GetInvitation returns', async ({ adminPage, sdk }) => {
    const email = uniqueEmail('detail');
    const created = await sdk.invitation.create({ email, role: 'member' });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const id = created.data!.invitation.id;
    expect(id).toBeTruthy();

    await adminPage.goto('/tenant/invitations');
    const row = adminPage.getByRole('row').filter({ hasText: email });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: /open menu/i }).click();

    const viewDetails = adminPage.getByRole('menuitem', { name: /view details/i });
    await expect(viewDetails).toHaveAttribute('data-capability-enabled', 'true');

    const detailRes = apiResponse(adminPage, new RegExp(`^/api/v1/invitations/${id}$`));
    await viewDetails.click();
    const res = await detailRes;
    expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();

    const dialog = adminPage.getByRole('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog).toContainText(email);
  });
});

test.describe('Invitation link', () => {
  test('the passkey page prefills the invited email', async ({ browser, baseURL, sdk }) => {
    const email = uniqueEmail('link');
    const created = await sdk.invitation.create({ email, role: 'member' });
    expect(created.success, JSON.stringify(created.error)).toBeTruthy();
    const token = invitationToken(created.data!.invitation, baseURL!);
    test.fixme(!token, 'the create reply carries neither the invitation token nor an inviteUrl with it');

    // A fresh context: the invitation link is opened with no session.
    const context = await browser.newContext({ baseURL, ignoreHTTPSErrors: true });
    try {
      const page = await context.newPage();
      const byToken = apiResponse(page, /^\/api\/v1\/invitations\/token\/[^/]+$/);
      await page.goto(`/auth/webauthn?invitation=${encodeURIComponent(token!)}`);
      const res = await byToken;
      expect(res.ok(), `${res.url()} answered ${res.status()}`).toBeTruthy();
      await expect(page.getByPlaceholder('Enter your email')).toHaveValue(email);
    } finally {
      await context.close();
    }
  });
});
