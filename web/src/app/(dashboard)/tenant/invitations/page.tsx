"use client";

import * as React from "react";
import {
  Crown,
  Mail,
  MailPlus,
  MoreHorizontal,
  RefreshCw,
  Shield,
  User,
  X,
  AlertCircle,
} from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";
import { PageHeader } from "@/components/layout/page-header";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable } from "@/components/ui/data-table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { InvitationForm } from "@/components/features/tenant/invitation-form";
import { useAuth } from "@/contexts/AuthContext";
import { useInvitation, useInvitationList, useToast } from "@/hooks";
import type { SendInvitationInput } from "@/types/tenant";
import type { Invitation, InvitationStatus } from "trusted-platform-sdk";

const roleIcons: Record<string, React.ElementType> = {
  owner: Crown,
  admin: Shield,
  member: User,
  viewer: User,
};

const statusColors: Record<InvitationStatus, "secondary" | "default" | "destructive" | "outline"> = {
  pending: "secondary",
  accepted: "default",
  expired: "destructive",
  revoked: "outline",
};

export default function InvitationsPage() {
  const { isLoading: authLoading } = useAuth();
  const { toast } = useToast();
  const [processingId, setProcessingId] = React.useState<string | null>(null);

  // Use SDK invitation hooks
  const { create, revoke, resend } = useInvitation();
  const {
    data: invitationsResponse,
    isLoading,
    error: apiError,
    refetch,
  } = useInvitationList({
    enabled: !authLoading,
  });

  // Extract invitations from response
  // Normalize the server's protobuf status enum
  // (`INVITATION_STATUS_PENDING`) to the lower-case strings the UI uses
  // for filtering, badge colors, and per-row actions.
  const invitations: Invitation[] = React.useMemo(() => {
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const raw = (invitationsResponse?.invitations || []) as any[];
    return raw.map((inv) => {
      const s = String(inv.status || '').toUpperCase();
      const status: Invitation["status"] = s.endsWith("PENDING")
        // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
        ? ("pending" as any)
        : s.endsWith("ACCEPTED")
          // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
          ? ("accepted" as any)
          : s.endsWith("REVOKED") || s.endsWith("CANCELLED")
            // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
            ? ("cancelled" as any)
            : s.endsWith("EXPIRED")
              // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
              ? ("expired" as any)
              // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
              : (inv.status as any);
      return { ...inv, status } as Invitation;
    });
  }, [invitationsResponse]);

  const error = apiError ? apiError.message : null;

  const handleSendInvitation = async (data: SendInvitationInput) => {
    try {
      await create.mutateAsync({
        email: data.email,
        role: data.role,
        expiresIn: 72, // 72 hours expiration
      });
      toast({
        title: "Invitation sent",
        description: `Invitation sent to ${data.email}`,
        variant: "success",
      });
      void refetch();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to send invitation";
      toast({
        title: "Failed to send invitation",
        description: errorMessage,
        variant: "destructive",
      });
      throw err;
    }
  };

  const handleResend = async (invitation: Invitation) => {
    setProcessingId(invitation.id);
    try {
      await resend.mutateAsync(invitation.id);
      toast({
        title: "Invitation resent",
        description: `Invitation resent to ${invitation.email}`,
        variant: "success",
      });
      void refetch();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to resend invitation";
      toast({
        title: "Failed to resend invitation",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setProcessingId(null);
    }
  };

  const handleCancel = async (id: string) => {
    if (!confirm("Are you sure you want to cancel this invitation?")) return;

    setProcessingId(id);
    try {
      await revoke.mutateAsync(id);
      toast({
        title: "Invitation cancelled",
        description: "The invitation has been revoked",
        variant: "success",
      });
      void refetch();
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Failed to cancel invitation";
      toast({
        title: "Failed to cancel invitation",
        description: errorMessage,
        variant: "destructive",
      });
    } finally {
      setProcessingId(null);
    }
  };

  const columns: ColumnDef<Invitation>[] = [
    {
      accessorKey: "email",
      header: "Email",
      cell: ({ row }) => {
        return (
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-muted-foreground" />
            <span className="font-medium">{row.original.email}</span>
          </div>
        );
      },
    },
    {
      accessorKey: "role",
      header: "Role",
      cell: ({ row }) => {
        const role = row.original.role;
        const Icon = roleIcons[role] || User;
        return (
          <div className="flex items-center gap-2">
            <Icon className="h-4 w-4" />
            <span className="capitalize">{role}</span>
          </div>
        );
      },
    },
    {
      accessorKey: "createdAt",
      header: "Invited",
      cell: ({ row }) => {
        const date = new Date(row.original.createdAt);
        return (
          <span className="text-sm text-muted-foreground">
            {date.toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
            })}
          </span>
        );
      },
    },
    {
      accessorKey: "expiresAt",
      header: "Expires",
      cell: ({ row }) => {
        const date = new Date(row.original.expiresAt);
        const now = new Date();
        const isExpired = date < now;

        return (
          <span
            className={`text-sm ${
              isExpired
                ? "text-destructive font-medium"
                : "text-muted-foreground"
            }`}
          >
            {date.toLocaleDateString("en-US", {
              month: "short",
              day: "numeric",
              year: "numeric",
            })}
          </span>
        );
      },
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => {
        const status = row.original.status;
        return (
          <Badge variant={statusColors[status] || "outline"}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        );
      },
    },
    {
      id: "actions",
      cell: ({ row }) => {
        const invitation = row.original;
        const isProcessing = processingId === invitation.id;
        const canResend = invitation.status === "pending" || invitation.status === "expired";
        const canCancel = invitation.status === "pending";

        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="h-8 w-8 p-0"
                disabled={isProcessing}
              >
                <span className="sr-only">Open menu</span>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              {canResend && (
                <DropdownMenuItem onClick={() => handleResend(invitation)}>
                  <RefreshCw className="h-4 w-4 mr-2" />
                  Resend Invitation
                </DropdownMenuItem>
              )}
              {canCancel && (
                <DropdownMenuItem
                  onClick={() => handleCancel(invitation.id)}
                  className="text-destructive focus:text-destructive"
                >
                  <X className="h-4 w-4 mr-2" />
                  Cancel Invitation
                </DropdownMenuItem>
              )}
              {!canResend && !canCancel && (
                <DropdownMenuItem disabled>
                  No actions available
                </DropdownMenuItem>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        );
      },
    },
  ];

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Invitations" description="Manage pending invitations" />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center text-center space-y-4">
              <AlertCircle className="h-12 w-12 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Error loading invitations</p>
                <p className="text-sm text-muted-foreground mt-1">{error}</p>
              </div>
              <Button onClick={() => refetch()} variant="outline">
                <RefreshCw className="h-4 w-4 mr-2" />
                Retry
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const pendingCount = invitations.filter((inv) => inv.status === "pending").length;
  const expiredCount = invitations.filter((inv) => inv.status === "expired").length;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeader
          title="Invitations"
          description="Manage and track member invitations"
        />
        <InvitationForm
          onSubmit={handleSendInvitation}
          trigger={
            <Button disabled={create.isLoading}>
              <MailPlus className="h-4 w-4 mr-2" />
              {create.isLoading ? "Sending..." : "Send Invitation"}
            </Button>
          }
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Invitations</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {isLoading || authLoading ? (
                <Skeleton className="h-8 w-12" />
              ) : (
                invitations.length
              )}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">
              {isLoading || authLoading ? (
                <Skeleton className="h-8 w-12" />
              ) : (
                pendingCount
              )}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Expired</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold text-destructive">
              {isLoading || authLoading ? (
                <Skeleton className="h-8 w-12" />
              ) : (
                expiredCount
              )}
            </p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Mail className="h-5 w-5" />
            All Invitations
          </CardTitle>
          <CardDescription>
            {isLoading || authLoading ? (
              <Skeleton className="h-4 w-48" />
            ) : (
              `${invitations.length} invitation${invitations.length !== 1 ? "s" : ""} sent`
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading || authLoading ? (
            <div className="space-y-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : invitations.length === 0 ? (
            <div className="text-center py-12">
              <Mail className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No invitations sent</p>
              <p className="text-sm text-muted-foreground mt-1">
                Send your first invitation to get started
              </p>
            </div>
          ) : (
            <DataTable
              columns={columns}
              data={invitations}
              searchKey="email"
              searchPlaceholder="Search by email..."
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
