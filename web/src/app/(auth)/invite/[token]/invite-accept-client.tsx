"use client";

import * as React from "react";
import { use } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { AlertCircle, CheckCircle2, Loader2, Mail } from "lucide-react";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { toInvitationView, useInvitation, useInvitationByToken } from "@/hooks";

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

  const [name, setName] = React.useState("");
  const [password, setPassword] = React.useState("");
  const [accepted, setAccepted] = React.useState(false);
  const [acceptError, setAcceptError] = React.useState<string | null>(null);

  const handleAccept = async (event: React.FormEvent) => {
    event.preventDefault();
    setAcceptError(null);
    try {
      const result = await accept.mutateAsync({
        token,
        ...(name ? { name } : {}),
        ...(password ? { password } : {}),
      });
      if (result && result.success === false) {
        setAcceptError(result.message || "The invitation could not be accepted");
        return;
      }
      setAccepted(true);
    } catch (err) {
      setAcceptError(err instanceof Error ? err.message : "Failed to accept invitation");
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
      {canAccept ? (
        <form onSubmit={handleAccept}>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="invite-name">Name</Label>
              <Input
                id="invite-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                autoComplete="name"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="invite-password">Password (new accounts only)</Label>
              <Input
                id="invite-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
              />
            </div>
            {acceptError && (
              <p role="alert" className="text-sm text-destructive">
                {acceptError}
              </p>
            )}
          </CardContent>
          <CardFooter>
            <Button type="submit" className="w-full" disabled={accept.isLoading}>
              {accept.isLoading ? "Accepting..." : "Accept Invitation"}
            </Button>
          </CardFooter>
        </form>
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
