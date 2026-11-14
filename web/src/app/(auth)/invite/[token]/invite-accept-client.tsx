"use client";

import * as React from "react";
import { use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AlertCircle, Loader2, Mail } from "lucide-react";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { toInvitationView, useInvitationByToken } from "@/hooks";
import { useSessionToken } from "@/hooks/use-session-token";
import { decodeJWT } from "@/utils/jwt";

// signedInUserId returns the numeric user ID of the signed-in session, or
// null when there is no session or its subject is not a decimal user ID.
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

// errorMessage reads the message of an SDK MutationError (a plain object,
// not an Error instance), with a fallback for any other value.
function passkeySignUpHref(token: string, tenantName?: string): string {
  let href = `/auth/webauthn?invitation=${encodeURIComponent(token)}`;
  if (tenantName) {
    href += `&tenant_name=${encodeURIComponent(tenantName)}`;
  }
  return href;
}

/**
 * Invitation accept page: looks the invitation up by its token
 * (GetInvitationByToken) and accepts it (AcceptInvitation).
 */
export default function InviteAcceptClient({ params }: { params: Promise<{ token: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const token = resolveDynamicId(resolved, pathname, "invite", "token");

  const { data, isLoading, error } = useInvitationByToken(token);
  const invitation = React.useMemo(() => toInvitationView(data), [data]);

  const sessionToken = useSessionToken();
  const signedInAs = React.useMemo(() => signedInUserId(sessionToken), [sessionToken]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[300px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error || !invitation) {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <AlertCircle className="h-12 w-12 mx-auto text-destructive" />
          <CardTitle>Invalid invitation</CardTitle>
          <CardDescription>
            {error?.message || "This invitation link is not valid."}
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const canAccept = invitation.status === "pending";

  // Only the passkey sign-up (RegisterInvitedUser) joins the user to the
  // tenant before it consumes the invitation. AcceptInvitation marks the
  // invitation accepted without granting membership, so this page never
  // calls it, and a signed-in session, which the sign-up would redirect to
  // the dashboard, is told so instead of being offered a dead end.
  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Mail className="h-5 w-5" />
          You have been invited
        </CardTitle>
        <CardDescription>
          {invitation.email} is invited to join{" "}
          <span className="font-medium">{invitation.tenantName || "a workspace"}</span> as{" "}
          <span className="font-medium">{invitation.role}</span>.
        </CardDescription>
      </CardHeader>
      {canAccept && signedInAs ? (
        <CardContent>
          <p role="status" className="text-sm text-muted-foreground">
            You are signed in as {signedInAs}. An existing account cannot join this workspace from
            an invitation link yet; ask the workspace administrator to add you, or sign out and
            create an account with a passkey for {invitation.email}.
          </p>
        </CardContent>
      ) : canAccept ? (
        <CardFooter>
          <Button asChild className="w-full">
            <Link href={passkeySignUpHref(token, invitation.tenantName)}>Create account with passkey</Link>
          </Button>
        </CardFooter>
      ) : (
        <CardContent>
          <p role="alert" className="text-sm text-muted-foreground">
            This invitation is {invitation.status} and can no longer be accepted.
          </p>
        </CardContent>
      )}
    </Card>
  );
}
