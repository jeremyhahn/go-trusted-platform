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

  // Codex round 2 (#1681): AcceptInvitation only marks the invitation accepted
  // and never joins the user to the tenant, so the page must not call it.
  test('AcceptInvitation: a numeric user ID session sends no accept', async ({ page }) => {
    await createCustomSession(page.context(), signedIn);
    const mock = await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-accept-1');
    await expect(page.getByRole('status')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
    expect(mock.acceptRequests()).toEqual([]);
  });

  // A login-issued session carries the login name in user_id and sub; the
  // passkey sign-up would redirect it to the dashboard, so it is not offered.
  test('AcceptInvitation: a login-issued session gets no passkey dead end and sends no accept', async ({ page }) => {
    await createCustomSession(page.context(), {
      sub: 'operator@platform',
      user_id: 'operator@platform',
      email: 'operator@platform',
      exp: Math.floor(Date.now() / 1000) + 3600,
    });
    const mock = await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-accept-1');
    await expect(page.getByRole('status').filter({ hasText: 'operator@platform' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Create account with passkey' })).toHaveCount(0);
    await expect(page.getByRole('button', { name: 'Accept Invitation' })).toHaveCount(0);
    expect(mock.acceptRequests()).toEqual([]);
  });

  test('AcceptInvitation: a signed-out visitor gets the passkey sign-up link', async ({ page }) => {
    await mockInvitationLookupApi(page, { invitation });

    await page.goto('/invite/tok-accept-1');
    await expect(page.getByRole('link', { name: 'Create account with passkey' })).toBeVisible();
  });
});
import { test, expect } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
  createMockInvitation,
  mockInvitationApi,
  mockInvitationLookupApi,
  mockTenantApi,
} from "./fixtures/api-mock";

/**
 * Invitation detail, lookup by token and accept flow (#1753, slice 19 of #1665).
 *
 * Operations:
 * - GetInvitation         GET  /invitations/{id}
 * - GetInvitationByToken  GET  /invitations/token/{token}
 * - AcceptInvitation      POST /invitations/accept
 */
test.describe("Invitation accept flow", () => {
  test("GetInvitation: invitation detail page shows the invitation", async ({ page }) => {
    await createTenantOwnerSession(page.context());
    const inv = createMockInvitation({ id: "inv-detail-1", email: "detail@example.com", role: "admin" });
    await mockTenantApi(page);
    await mockInvitationApi(page, { initialInvitations: [inv] });
    await mockInvitationLookupApi(page, { invitations: [inv] });

    await page.goto("/admin/invitations");
    await page.getByTestId("view-invitation-inv-detail-1").click();

    await expect(page).toHaveURL(/\/admin\/invitations\/detail\/?\?id=inv-detail-1/);
    await expect(page.getByTestId("invitation-detail-id")).toHaveText("inv-detail-1");
    await expect(page.getByTestId("invitation-detail-email")).toHaveText("detail@example.com");
    await expect(page.getByTestId("invitation-detail-role")).toHaveText("admin");
    await expect(page.getByTestId("invitation-detail-status")).toHaveText("pending");
  });

  test("GetInvitation: unknown id shows the error", async ({ page }) => {
    await createTenantOwnerSession(page.context());
    await mockTenantApi(page);
    await mockInvitationApi(page);
    await mockInvitationLookupApi(page, { invitations: [] });

    await page.goto("/admin/invitations/detail/?id=missing");
    await expect(page.getByTestId("invitation-detail-error")).toContainText("Invitation not found");
  });

  test("GetInvitationByToken: public invite page looks the invitation up by token", async ({ page }) => {
    const inv = createMockInvitation({ id: "inv-tok-1", token: "tok-abc", email: "invitee@example.com" });
    await mockInvitationLookupApi(page, { invitations: [inv], tenantName: "Acme Workspace" });

    await page.goto("/invite/?token=tok-abc");

    await expect(page.getByTestId("invite-email")).toHaveText("invitee@example.com");
    await expect(page.getByTestId("invite-role")).toHaveText("member");
    await expect(page.getByTestId("invite-tenant")).toHaveText("Acme Workspace");
    await expect(page.getByTestId("invite-join")).toHaveAttribute(
      "href",
      "/auth/webauthn/?invitation=tok-abc&tenant_name=Acme%20Workspace"
    );
  });

  test("GetInvitationByToken: an unknown token shows the error and no join link", async ({ page }) => {
    await mockInvitationLookupApi(page, { invitations: [] });

    await page.goto("/invite/?token=nope");

    await expect(page.getByTestId("invite-error")).toContainText("Invalid or expired invitation");
    await expect(page.getByTestId("invite-join")).toHaveCount(0);
  });

  test("AcceptInvitation: the join link is the registration flow and posts nothing to /invitations/accept", async ({
    page,
  }) => {
    const inv = createMockInvitation({ id: "inv-join-1", token: "tok-join" });
    const mock = await mockInvitationLookupApi(page, { invitations: [inv], tenantName: "Acme Workspace" });

    await page.goto("/invite/?token=tok-join");

    const join = page.getByTestId("invite-join");
    await expect(join).toHaveAttribute("href", "/auth/webauthn/?invitation=tok-join&tenant_name=Acme%20Workspace");
    await join.click();

    // The registration flow (BeginRegistration with invitation_token) joins
    // the invitee and consumes the invitation; the invite page never calls
    // AcceptInvitation itself.
    await expect(page).toHaveURL(/\/auth\/webauthn\/\?invitation=tok-join/);
    expect(mock.acceptBodies()).toHaveLength(0);
  });
});
