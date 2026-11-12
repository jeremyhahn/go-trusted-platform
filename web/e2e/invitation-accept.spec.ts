import { test } from "@playwright/test";

/**
 * Invitation detail, lookup by token and accept flow (#1753, slice 19 of #1665).
 *
 * Operations:
 * - GetInvitation         GET  /invitations/{id}
 * - GetInvitationByToken  GET  /invitations/token/{token}
 * - AcceptInvitation      POST /invitations/accept
 */
test.describe("Invitation accept flow", () => {
  test.fixme("GetInvitation: invitation detail page shows the invitation", async () => {});
  test.fixme("GetInvitationByToken: public invite page looks the invitation up by token", async () => {});
  test.fixme("AcceptInvitation: accept behind a confirm dialog posts the token", async () => {});
});
