import { test, expect } from "@playwright/test";
import { createTenantOwnerSession } from "./fixtures/auth-setup";
import {
  createMockInvitation,
  mockInvitationApi,
  mockInvitationFlowApi,
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
    await mockInvitationFlowApi(page, { invitations: [inv] });

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
    await mockInvitationFlowApi(page, { invitations: [] });

    await page.goto("/admin/invitations/detail/?id=missing");
    await expect(page.getByTestId("invitation-detail-error")).toContainText("Invitation not found");
  });

  test("GetInvitationByToken: public invite page looks the invitation up by token", async ({ page }) => {
    const inv = createMockInvitation({ id: "inv-tok-1", token: "tok-abc", email: "invitee@example.com" });
    await mockInvitationFlowApi(page, { invitations: [inv], tenantName: "Acme Workspace" });

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
    await mockInvitationFlowApi(page, { invitations: [] });

    await page.goto("/invite/?token=nope");

    await expect(page.getByTestId("invite-error")).toContainText("Invalid or expired invitation");
    await expect(page.getByTestId("invite-join")).toHaveCount(0);
  });

  test("AcceptInvitation: the join link is the registration flow and posts nothing to /invitations/accept", async ({
    page,
  }) => {
    const inv = createMockInvitation({ id: "inv-join-1", token: "tok-join" });
    const mock = await mockInvitationFlowApi(page, { invitations: [inv], tenantName: "Acme Workspace" });

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
