import { test, expect } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
import {
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
    await expect(page.getByTestId("invite-accept")).toBeVisible();
  });

  test("GetInvitationByToken: an unknown token shows the error and no accept button", async ({ page }) => {
    await mockInvitationLookupApi(page, { invitations: [] });

    await page.goto("/invite/?token=nope");

    await expect(page.getByTestId("invite-error")).toContainText("Invalid or expired invitation");
    await expect(page.getByTestId("invite-accept")).toHaveCount(0);
  });

  test("AcceptInvitation: accept behind a confirm dialog posts the token and user_id", async ({ page }) => {
    await createTenantOwnerSession(page.context(), { userId: "invitee-user-1" });
    const inv = createMockInvitation({ id: "inv-acc-1", token: "tok-accept" });
    const mock = await mockInvitationLookupApi(page, { invitations: [inv] });

    await page.goto("/invite/?token=tok-accept");
    await page.getByTestId("invite-accept").click();

    // Cancelling the dialog posts nothing.
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(page.getByRole("dialog")).toHaveCount(0);
    expect(mock.acceptBodies()).toHaveLength(0);

    await page.getByTestId("invite-accept").click();
    await page.getByTestId("invite-confirm").click();

    await expect(page.getByTestId("invite-accepted")).toHaveText("Invitation accepted");
    expect(mock.acceptBodies()).toEqual([{ token: "tok-accept", user_id: "invitee-user-1" }]);
    await expect(page.getByTestId("invite-accept")).toHaveCount(0);
  });

  test("AcceptInvitation: signed out, the page links to sign-in and posts nothing", async ({ page }) => {
    const inv = createMockInvitation({ id: "inv-acc-3", token: "tok-signin" });
    const mock = await mockInvitationLookupApi(page, { invitations: [inv] });

    await page.goto("/invite/?token=tok-signin");

    const signIn = page.getByTestId("invite-sign-in");
    await expect(signIn).toBeVisible();
    await expect(signIn).toHaveAttribute(
      "href",
      `/auth/login/?redirect=${encodeURIComponent("/invite/?token=tok-signin")}`
    );
    await expect(page.getByTestId("invite-accept")).toHaveCount(0);
    expect(mock.acceptBodies()).toHaveLength(0);
  });

  test("AcceptInvitation: a refused accept shows the error", async ({ page }) => {
    await createTenantOwnerSession(page.context());
    const inv = createMockInvitation({ id: "inv-acc-2", token: "tok-refused" });
    await mockInvitationLookupApi(page, {
      invitations: [inv],
      acceptError: { error: "Invitation has expired", status: 410 },
    });

    await page.goto("/invite/?token=tok-refused");
    await page.getByTestId("invite-accept").click();
    await page.getByTestId("invite-confirm").click();

    await expect(page.getByTestId("invite-accept-error")).toHaveText("Invitation has expired");
  });
});
