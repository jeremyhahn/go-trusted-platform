import { test, expect } from '@playwright/test';
import {
  createMockInvitation,
  mockAllApis,
  mockInvitationLookupApi,
} from './fixtures/api-mock';
import { createCustomSession, setupTenantOwnerPage } from './fixtures/auth-setup';

// Slice 19 of epic #1665: invitation lookup and accept pages (#1671).
test.describe('Invitation lookup and accept', () => {
  const invitation = createMockInvitation({
    id: 'inv-detail-1',
    email: 'invitee@example.com',
    role: 'admin',
    status: 'pending',
    token: 'tok-accept-1',
  });
  const signedIn = {
    sub: '9',
    user_id: '9',
    email: 'invitee@example.com',
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  test('GetInvitation: detail page shows an invitation by id', async ({ page }) => {
    await setupTenantOwnerPage(page);
    await mockAllApis(page, { invitation: { initialInvitations: [invitation] } });
    await mockInvitationLookupApi(page, { invitation });

    const lookup = page.waitForRequest(
      (req) => req.method() === 'GET' && /\/api\/v1\/invitations\/inv-detail-1\/?(\?|$)/.test(req.url())
    );
    await page.goto('/tenant/invitations/inv-detail-1');
    await lookup;

    await expect(page.getByRole('heading', { name: 'Invitation Details' })).toBeVisible();
    await expect(page.getByText('invitee@example.com').first()).toBeVisible();
    await expect(page.getByTestId('invitation-status')).toHaveText('Pending');
  });

  test('GetInvitation: unknown id shows an error', async ({ page }) => {
    await setupTenantOwnerPage(page);
    await mockAllApis(page);
    await mockInvitationLookupApi(page, { invitation });

    await page.goto('/tenant/invitations/inv-missing');
    await expect(page.getByText('Error loading invitation')).toBeVisible();
  });

  test('GetInvitationByToken: invite page shows the invitation for a token', async ({ page }) => {
    await mockInvitationLookupApi(page, { invitation });

    const lookup = page.waitForRequest((req) =>
      /\/api\/v1\/invitations\/token\/tok-accept-1\/?(\?|$)/.test(req.url())
    );
    await page.goto('/invite/tok-accept-1');
    await lookup;

    await expect(page.getByText('You have been invited')).toBeVisible();
    await expect(page.getByText(/invitee@example\.com is invited/)).toBeVisible();
    const signUp = page.getByRole('link', { name: 'Create account with passkey' });
    await expect(signUp).toBeVisible();
    await expect(signUp).toHaveAttribute('href', /\/auth\/webauthn\?invitation=tok-accept-1/);
    await expect(page.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
  });

  test('GetInvitationByToken: unknown token shows an invalid invitation', async ({ page }) => {
    await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-unknown');
    await expect(page.getByText('Invalid invitation')).toBeVisible();
  });

  test('AcceptInvitation: a signed-in user accepts with their user ID', async ({ page }) => {
    await createCustomSession(page.context(), signedIn);
    const mock = await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-accept-1');
    await page.getByRole('button', { name: 'Accept Invitation' }).click();

    await expect(page.getByText('Invitation accepted')).toBeVisible();
    expect(mock.acceptRequests()).toEqual([{ token: 'tok-accept-1', userId: '9' }]);
  });

  test('AcceptInvitation: a refused accept shows the error', async ({ page }) => {
    await createCustomSession(page.context(), signedIn);
    await mockInvitationLookupApi(page, {
      invitation,
      acceptError: { status: 409, error: 'invitation already accepted', errorCode: 'CONFLICT' },
    });

    await page.goto('/invite/tok-accept-1');
    await page.getByRole('button', { name: 'Accept Invitation' }).click();

    await expect(page.getByRole('alert').filter({ hasText: 'invitation already accepted' })).toBeVisible();
  });

  test('AcceptInvitation: a non-numeric subject gets the passkey link and sends no accept', async ({ page }) => {
    await createCustomSession(page.context(), {
      sub: 'operator@platform',
      email: 'invitee@example.com',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const mock = await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-accept-1');
    await expect(page.getByRole('link', { name: 'Create account with passkey' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
    expect(mock.acceptRequests()).toEqual([]);
  });
});
