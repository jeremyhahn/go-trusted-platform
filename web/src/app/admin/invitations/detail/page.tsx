"use client";

import { Suspense, useMemo } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { toInvitationView, useInvitationById } from "@/hooks";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui";

/**
 * Invitation detail (GetInvitation, #1753). The id travels as a query
 * parameter (`/admin/invitations/detail/?id=...`): the site is a static
 * export and cannot serve an unlisted dynamic segment.
 */
function InvitationDetailView() {
  const params = useSearchParams();
  const id = params.get("id");
  // The SDK client loads the invitation (service.get); an SDK error is shown
  // as it is, never retried with a hand-written fetch.
  const { data, isLoading: loading, error: apiError } = useInvitationById(id ?? "");
  const invitation = useMemo(() => toInvitationView(data), [data]);
  const error = !id ? "No invitation was named" : apiError?.message ?? null;

  return (
    <Card data-testid="invitation-detail">
      <CardHeader>
        <CardTitle>Invitation</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {loading && <p>Loading invitation...</p>}
        {!loading && error && (
          <p role="alert" data-testid="invitation-detail-error">
            {error}
          </p>
        )}
        {!loading && invitation && (
          <dl className="grid grid-cols-2 gap-2 text-sm">
            <dt>ID</dt>
            <dd data-testid="invitation-detail-id">{invitation.id}</dd>
            <dt>Email</dt>
            <dd data-testid="invitation-detail-email">{invitation.email}</dd>
            <dt>Role</dt>
            <dd data-testid="invitation-detail-role">{invitation.role}</dd>
            <dt>Status</dt>
            <dd data-testid="invitation-detail-status">{invitation.status}</dd>
            {invitation.expiresAt && (
              <>
                <dt>Expires</dt>
                <dd>{new Date(invitation.expiresAt).toLocaleString()}</dd>
              </>
            )}
          </dl>
        )}
        <Link href="/admin/invitations">Back to invitations</Link>
      </CardContent>
    </Card>
  );
}

export default function InvitationDetailPage() {
  return (
    <Suspense fallback={<p>Loading invitation...</p>}>
      <InvitationDetailView />
    </Suspense>
  );
}
