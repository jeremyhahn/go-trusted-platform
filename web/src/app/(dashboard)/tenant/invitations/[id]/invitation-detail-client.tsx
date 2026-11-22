"use client";

import * as React from "react";
import { use } from "react";
import { usePathname, useRouter } from "next/navigation";
import { AlertCircle, ArrowLeft, Loader2, Mail } from "lucide-react";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { toInvitationView, useInvitationById } from "@/hooks";

const statusColors: Record<string, "secondary" | "default" | "destructive" | "outline"> = {
  pending: "secondary",
  accepted: "default",
  expired: "destructive",
  revoked: "outline",
};

function formatDate(value: string): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * Invitation detail page (GetInvitation).
 */
export default function InvitationDetailClient({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const id = resolveDynamicId(resolved, pathname, "invitations");
  const router = useRouter();

  const { data, isLoading, error, refetch } = useInvitationById(id);
  const invitation = React.useMemo(() => toInvitationView(data), [data]);

  const back = (
    <Button variant="outline" onClick={() => router.push("/tenant/invitations")}>
      <ArrowLeft className="mr-2 h-4 w-4" />
      Back to Invitations
    </Button>
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <AlertCircle className="h-12 w-12 text-destructive" />
        <div className="text-center">
          <p className="font-medium text-destructive">Error loading invitation</p>
          <p className="text-sm text-muted-foreground">{error.message}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void refetch()}>
            Retry
          </Button>
          {back}
        </div>
      </div>
    );
  }

  if (!invitation) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <p className="text-muted-foreground">Invitation not found</p>
        {back}
      </div>
    );
  }

  const rows: Array<[string, string]> = [
    ["Email", invitation.email],
    ["Role", invitation.role],
    ["Tenant", invitation.tenantName || invitation.tenantId || "—"],
    ["Invited", formatDate(invitation.createdAt)],
    ["Expires", formatDate(invitation.expiresAt)],
    ["Accepted", formatDate(invitation.acceptedAt)],
    ["Invited by", invitation.invitedById || "—"],
  ];

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          aria-label="Back to Invitations"
          onClick={() => router.push("/tenant/invitations")}
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Invitation Details</h1>
          <p className="text-muted-foreground">{invitation.id}</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            {invitation.email}
          </CardTitle>
          <CardDescription>
            <Badge variant={statusColors[invitation.status] || "outline"} data-testid="invitation-status">
              {invitation.status.charAt(0).toUpperCase() + invitation.status.slice(1)}
            </Badge>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl className="grid gap-3 sm:grid-cols-2">
            {rows.map(([label, value]) => (
              <div key={label}>
                <dt className="text-sm text-muted-foreground">{label}</dt>
                <dd className="font-medium">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
