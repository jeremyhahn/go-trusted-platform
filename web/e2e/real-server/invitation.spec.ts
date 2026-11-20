import { test, expect } from './fixtures';

// #2056 (epic #1665, coverage-matrix slice 19): InvitationService.GetInvitation,
// GetInvitationByToken and AcceptInvitation against the real server.
// State is seeded through the SDK, never through route mocks.
//
// AcceptInvitation only marks an invitation accepted; it grants no tenant
// membership, so the web control for it is gated off (disabled, with the
// reason) and joining goes through passkey sign-up. The spec checks that the
// gated control never accepts: the server still reports the invitation pending.

type Wire = { id?: string; token?: string; email?: string; status?: string };

function invitationOf(data: unknown): Wire {
  const body = (data ?? {}) as { invitation?: Wire };
  return body.invitation ?? (body as Wire);
}

function isPending(status: string | undefined): boolean {
  return /pending/i.test(status ?? '');
}

test.describe('invitation operations (#2056)', () => {
  test('GetInvitation: the detail page shows what the server returns', async ({ adminPage, sdk }) => {
    const email = `invitee-get-${Date.now()}@example.com`;
    const created = await sdk.invitation.create({ email, role: 'member' });
    expect(created.success).toBe(true);
    const inv = invitationOf(created.data);
    expect(inv.id).toBeTruthy();

    const got = await sdk.invitation.get(String(inv.id));
    expect(got.success).toBe(true);
    const fromServer = invitationOf(got.data);
    expect(fromServer.email).toBe(email);
    expect(isPending(fromServer.status)).toBe(true);

    await adminPage.goto(`/tenant/invitations/${inv.id}`);
    await expect(adminPage.getByRole('heading', { name: /invitation details/i })).toBeVisible();
    await expect(adminPage.getByText(email)).toBeVisible();
    await expect(adminPage.getByTestId('invitation-status')).toHaveText(/pending/i);
  });

  test('GetInvitationByToken: a signed-out visitor sees the invitation and the passkey sign-up', async ({
    browser,
    sdk,
  }) => {
    const email = `invitee-token-${Date.now()}@example.com`;
    const created = await sdk.invitation.create({ email, role: 'member' });
    expect(created.success).toBe(true);
    const inv = invitationOf(created.data);
    expect(inv.token).toBeTruthy();

    const byToken = await sdk.invitation.getByToken(String(inv.token));
    expect(byToken.success).toBe(true);
    expect(invitationOf(byToken.data).email).toBe(email);

    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.goto(`/invite/${inv.token}`);
      await expect(page.getByText(/you have been invited/i)).toBeVisible();
      const signUp = page.getByRole('link', { name: /create account with passkey/i });
      await expect(signUp).toBeVisible();
      await expect(signUp).toHaveAttribute('href', new RegExp(`invitation=${inv.token}`));
    } finally {
      await context.close();
    }
  });

  test('GetInvitationByToken: an unknown token shows the server refusal', async ({ browser }) => {
    const context = await browser.newContext();
    try {
      const page = await context.newPage();
      await page.goto(`/invite/no-such-token-${Date.now()}`);
      await expect(page.getByText(/invalid invitation/i)).toBeVisible();
    } finally {
      await context.close();
    }
  });

  test('AcceptInvitation: the control is gated off with its reason and accepts nothing', async ({
    adminPage,
    sdk,
  }) => {
    const email = `invitee-accept-${Date.now()}@example.com`;
    const created = await sdk.invitation.create({ email, role: 'member' });
    expect(created.success).toBe(true);
    const inv = invitationOf(created.data);

    await adminPage.goto(`/invite/${inv.token}`);
    const accept = adminPage.getByRole('button', { name: /accept with this account/i });
    await expect(accept).toBeVisible();
    await expect(accept).toBeDisabled();
    const reasonId = await accept.getAttribute('aria-describedby');
    expect(reasonId).toBeTruthy();
    await expect(adminPage.locator(`[id="${reasonId}"]`)).toContainText(/passkey/i);

    const after = await sdk.invitation.getByToken(String(inv.token));
    expect(after.success).toBe(true);
    expect(isPending(invitationOf(after.data).status)).toBe(true);
  });
});
