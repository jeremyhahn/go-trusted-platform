"use client";

import { Suspense, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import { isPendingInvitation, useInvitationLookup } from "@/hooks";
import { useSessionToken } from "@/hooks/use-session-token";
import { decodeJWT } from "@/utils/jwt";
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
// signedInUserId returns the user ID of the signed-in session, or null when
// there is no session or its token carries no subject.
function signedInUserId(sessionToken: string | null): string | null {
  if (!sessionToken) {
    return null;
  }
  // The login issuer (pkg/webservice/v1/jwt/session_issuer.go) puts the
  // principal's login name, normally an email, into both user_id and sub.
  const payload = decodeJWT(sessionToken);
  const id = payload?.user_id ?? payload?.sub;
  return typeof id === "string" && id !== "" ? id : null;
}

function InviteAccept() {
  const params = useSearchParams();
  const token = params.get("token");
  const { invitation, loading, error } = useInvitationLookup({ token });
  // The passkey sign-up redirects a browser with a session to /dashboard
  // before it processes the invitation, so a signed-in invitee gets a notice.
  const sessionToken = useSessionToken();
  const signedInAs = useMemo(() => signedInUserId(sessionToken), [sessionToken]);
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
            signedInAs ? (
              <p role="status" data-testid="invite-signed-in" className="text-sm text-muted-foreground">
                You are signed in as {signedInAs}. An existing account cannot join this workspace from
                an invitation link yet; ask the workspace administrator to add you, or sign out and
                create an account with a passkey for {invitation.email}.
              </p>
            ) : (
              <div className="space-y-2">
                <a href={joinHref} data-testid="invite-join" className="underline">
                  Join workspace
                </a>
                <p className="text-sm text-muted-foreground">
                  You will create your account and join as {invitation.role}.
                </p>
              </div>
            )
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
