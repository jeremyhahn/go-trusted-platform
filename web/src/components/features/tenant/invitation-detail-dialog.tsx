"use client";

import * as React from "react";
import { useInvitationGet } from "trusted-platform-sdk";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";

export interface InvitationDetailDialogProps {
  /** The invitation to read; nothing is read while null. */
  id: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// The REST endpoint emits the status as an enum name such as
// "INVITATION_STATUS_PENDING" (#445); show it as the UI's lower-case word.
function statusWord(status: unknown): string {
  const s = String(status ?? "");
  return s.replace(/^INVITATION_STATUS_/, "").toLowerCase();
}

function when(value?: string): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("en-US");
}

/**
 * InvitationDetailDialog reads one invitation through GetInvitation
 * (GET /api/v1/invitations/{id}) and shows what the server holds for it.
 */
export function InvitationDetailDialog({ id, open, onOpenChange }: InvitationDetailDialogProps) {
  const { data, isLoading, error } = useInvitationGet(open && id ? id : undefined);
  const invitation = data?.invitation;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invitation details</DialogTitle>
          <DialogDescription>What the server holds for this invitation.</DialogDescription>
        </DialogHeader>
        {error ? (
          <p role="alert" className="text-sm text-destructive">
            {error.message}
          </p>
        ) : isLoading || !invitation ? (
          <div className="space-y-2" data-testid="invitation-detail-loading">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-32" />
            <Skeleton className="h-4 w-64" />
          </div>
        ) : (
          <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Email</dt>
            <dd>{invitation.email}</dd>
            <dt className="text-muted-foreground">Role</dt>
            <dd className="capitalize">{invitation.role}</dd>
            <dt className="text-muted-foreground">Status</dt>
            <dd>{statusWord(invitation.status)}</dd>
            <dt className="text-muted-foreground">Expires</dt>
            <dd>{when(invitation.expiresAt)}</dd>
            <dt className="text-muted-foreground">Accepted</dt>
            <dd>{when(invitation.acceptedAt)}</dd>
            <dt className="text-muted-foreground">Invite URL</dt>
            <dd className="break-all font-mono text-xs">{invitation.inviteUrl ?? "—"}</dd>
          </dl>
        )}
      </DialogContent>
    </Dialog>
  );
}
