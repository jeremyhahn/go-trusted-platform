"use client";

import * as React from "react";
import { use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AlertCircle, CheckCircle2, Loader2, Mail } from "lucide-react";
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
import { toInvitationView, useInvitation, useInvitationByToken } from "@/hooks";
import { useSessionToken } from "@/hooks/use-session-token";
import { decodeJWT } from "@/utils/jwt";

// signedInUserId returns the numeric user ID of the signed-in session, or
// null when there is no session or its subject is not a decimal user ID.
function signedInUserId(sessionToken: string | null): string | null {
  if (!sessionToken) {
    return null;
  }
  const payload = decodeJWT(sessionToken);
  const id = payload?.user_id ?? payload?.sub;
  return typeof id === "string" && /^[1-9][0-9]*$/.test(id) ? id : null;
}

// errorMessage reads the message of an SDK MutationError (a plain object,
// not an Error instance), with a fallback for any other value.
function errorMessage(err: unknown, fallback: string): string {
  if (
    err &&
    typeof err === "object" &&
    "message" in err &&
    typeof (err as { message: unknown }).message === "string" &&
    (err as { message: string }).message
  ) {
    return (err as { message: string }).message;
  }
  return fallback;
}

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
  const { accept } = useInvitation();

  const sessionToken = useSessionToken();
  const userId = React.useMemo(() => signedInUserId(sessionToken), [sessionToken]);
  const [accepted, setAccepted] = React.useState(false);
  const [acceptError, setAcceptError] = React.useState<string | null>(null);

  const handleAccept = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!userId) {
      return;
    }
    setAcceptError(null);
    try {
      const result = await accept.mutateAsync({ token, userId });
      if (result && result.success === false) {
        setAcceptError(result.message || "The invitation could not be accepted");
        return;
      }
      setAccepted(true);
    } catch (err) {
      setAcceptError(errorMessage(err, "Failed to accept invitation"));
    }
  };

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

  if (accepted) {
    return (
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <CheckCircle2 className="h-12 w-12 mx-auto text-green-600" />
          <CardTitle>Invitation accepted</CardTitle>
          <CardDescription>
            You have joined {invitation.tenantName || "the workspace"} as {invitation.role}.
          </CardDescription>
        </CardHeader>
        <CardFooter className="justify-center">
          <Button asChild>
            <Link href="/auth/login">Continue to sign in</Link>
          </Button>
        </CardFooter>
      </Card>
    );
  }

  const canAccept = invitation.status === "pending";

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
      {canAccept && userId ? (
        <form onSubmit={handleAccept}>
          {acceptError && (
            <CardContent>
              <p role="alert" className="text-sm text-destructive">
                {acceptError}
              </p>
            </CardContent>
          )}
          <CardFooter>
            <Button type="submit" className="w-full" disabled={accept.isLoading}>
              {accept.isLoading ? "Accepting..." : "Accept Invitation"}
            </Button>
          </CardFooter>
        </form>
      ) : canAccept ? (
        <>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Already have an account?{" "}
              <Link href="/auth/login" className="underline">
                Sign in
              </Link>
              , then open this link again.
            </p>
          </CardContent>
          <CardFooter>
            <Button asChild className="w-full">
              <Link href={passkeySignUpHref(token, invitation.tenantName)}>Create account with passkey</Link>
            </Button>
          </CardFooter>
        </>
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
