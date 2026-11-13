"use client";

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { isPendingInvitation, useInvitationLookup } from "@/hooks";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui";

/**
 * Public invitation accept page (#1753). Like the login page it sits
 * outside the dashboard layout: the invitee has no session yet.
 *
 * The token travels as a query parameter (`/invite/?token=...`) because the
 * site is a static export, which cannot serve an unlisted dynamic segment.
 *
 * The page does not call AcceptInvitation: that only marks the invitation
 * used. It links the invitee to the WebAuthn registration flow with the
 * token, where BeginRegistration carries `invitation_token` and the server's
 * RegisterInvitedUser grants the tenant and role and consumes the invitation.
 */
function InviteAccept() {
  const params = useSearchParams();
  const token = params.get("token");
  const { invitation, loading, error } = useInvitationLookup({ token });
  const joinHref = `/auth/webauthn/?invitation=${encodeURIComponent(token ?? "")}${
    invitation?.tenant_name ? `&tenant_name=${encodeURIComponent(invitation.tenant_name)}` : ""
  }`;

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md" data-testid="invite-card">
        <CardHeader>
          <CardTitle>Accept invitation</CardTitle>
          <CardDescription>Join the workspace you were invited to.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {loading && <p data-testid="invite-loading">Loading invitation...</p>}
          {!loading && error && (
            <p role="alert" data-testid="invite-error">
              {error}
            </p>
          )}
          {!loading && invitation && (
            <dl className="grid grid-cols-2 gap-2 text-sm" data-testid="invite-details">
              <dt>Email</dt>
              <dd data-testid="invite-email">{invitation.email}</dd>
              <dt>Role</dt>
              <dd data-testid="invite-role">{invitation.role}</dd>
              <dt>Status</dt>
              <dd data-testid="invite-status">{invitation.status}</dd>
              {invitation.tenant_name && (
                <>
                  <dt>Workspace</dt>
                  <dd data-testid="invite-tenant">{invitation.tenant_name}</dd>
                </>
              )}
            </dl>
          )}
          {!loading && invitation && isPendingInvitation(invitation.status) && (
            <div className="space-y-2">
              <a href={joinHref} data-testid="invite-join" className="underline">
                Join workspace
              </a>
              <p className="text-sm text-muted-foreground">
                You will create your account and join as {invitation.role}.
              </p>
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}

export default function InvitePage() {
  return (
    <Suspense fallback={<p>Loading invitation...</p>}>
      <InviteAccept />
    </Suspense>
  );
}
