"use client";

import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { acceptInvitation, isPendingInvitation, useInvitationLookup } from "@/hooks";
import { AuthProvider, useOptionalAuth } from "@/contexts/AuthContext";
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui";

/**
 * Public invitation accept page (#1753). Like the login page it sits
 * outside the dashboard layout: the invitee has no session yet.
 *
 * The token travels as a query parameter (`/invite/?token=...`) because the
 * site is a static export, which cannot serve an unlisted dynamic segment.
 */
function InviteAccept() {
  const params = useSearchParams();
  const token = params.get("token");
  const { invitation, loading, error } = useInvitationLookup({ token });
  const userId = useOptionalAuth()?.user?.id ?? null;
  const signInHref = `/auth/login/?redirect=${encodeURIComponent(
    `/invite/?token=${encodeURIComponent(token ?? "")}`
  )}`;
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [accepting, setAccepting] = useState(false);
  const [acceptError, setAcceptError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState<string | null>(null);

  const onConfirm = async () => {
    if (!token || !userId) return;
    setAccepting(true);
    setAcceptError(null);
    try {
      const result = await acceptInvitation(token, userId);
      setAccepted(result.message || "Invitation accepted");
      setConfirmOpen(false);
    } catch (err) {
      setAcceptError(err instanceof Error ? err.message : "Failed to accept invitation");
      setConfirmOpen(false);
    } finally {
      setAccepting(false);
    }
  };

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
          {accepted && (
            <p role="status" data-testid="invite-accepted">
              {accepted}
            </p>
          )}
          {acceptError && (
            <p role="alert" data-testid="invite-accept-error">
              {acceptError}
            </p>
          )}
          {!loading && invitation && isPendingInvitation(invitation.status) && !accepted && !userId && (
            <a href={signInHref} data-testid="invite-sign-in" className="underline">
              Sign in to accept
            </a>
          )}
          {!loading && invitation && isPendingInvitation(invitation.status) && !accepted && userId && (
            <div className="space-y-2">
              <Button onClick={() => setConfirmOpen(true)} data-testid="invite-accept">
                Accept invitation
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Accept this invitation?</DialogTitle>
            <DialogDescription>
              You will join the workspace as {invitation?.role ?? "a member"}. The invitation
              cannot be used again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={onConfirm} disabled={accepting} data-testid="invite-confirm">
              {accepting ? "Accepting..." : "Confirm"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </main>
  );
}

export default function InvitePage() {
  return (
    <AuthProvider>
      <Suspense fallback={<p>Loading invitation...</p>}>
        <InviteAccept />
      </Suspense>
    </AuthProvider>
  );
}
