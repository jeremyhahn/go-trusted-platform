"use client";

import * as React from "react";
import { UserPlus, Users, AlertCircle, RefreshCw } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { MemberTable } from "@/components/features/tenant/member-table";
import { InvitationForm } from "@/components/features/tenant/invitation-form";
import { useAuth } from "@/contexts/AuthContext";
import { useIAM, useApi, useMutation, useToast } from "@/hooks";
import type { IAMUser } from "trusted-platform-sdk";
import type { Member, TenantRole, SendInvitationInput } from "@/types/tenant";

export default function MembersPage() {
  const { tenantId, isLoading: authLoading } = useAuth();
  const { toast } = useToast();
  const iam = useIAM();

  // Fetch members (users) for the current tenant
  const {
    data: usersResponse,
    isLoading,
    error: apiError,
    refetch,
  } = useApi(
    () => iam.listUsers({ tenantId: tenantId || "", page: 1, pageSize: 100 }),
    [tenantId],
    { enabled: !!tenantId && !authLoading }
  );

  // Transform IAM users to Member format for UI compatibility
  const members: Member[] = React.useMemo(() => {
    if (!usersResponse?.users) return [];
    return usersResponse.users.map((user: IAMUser): Member => ({
      id: user.id,
      userId: user.id,
      user: {
        id: user.id,
        email: user.email,
        name: user.name || user.email,
      },
      role: (user.roles?.[0] || "viewer") as TenantRole,
      joinedAt: user.createdAt || new Date().toISOString(),
    }));
  }, [usersResponse]);

  const error = apiError ? apiError.message : null;

  // Update member role mutation
  const updateRoleMutation = useMutation(
    ({ userId, role }: { userId: string; role: TenantRole }) =>
      iam.assignRole({ tenantId: tenantId || "", userId, roleId: role }),
    {
      onSuccess: () => {
        toast({
          title: "Role updated",
          description: "Member role has been updated successfully",
          variant: "success",
        });
        void refetch();
      },
      onError: (error: { message: string }) => {
        toast({
          title: "Failed to update role",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  // Remove member mutation
  const removeMemberMutation = useMutation(
    (userId: string) => iam.deleteUser(tenantId || "", userId),
    {
      onSuccess: () => {
        toast({
          title: "Member removed",
          description: "Member has been removed from the tenant",
          variant: "success",
        });
        void refetch();
      },
      onError: (error: { message: string }) => {
        toast({
          title: "Failed to remove member",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleRoleChange = async (memberId: string, role: TenantRole) => {
    if (!tenantId) {
      throw new Error("No tenant context");
    }
    updateRoleMutation.mutate({ userId: memberId, role });
  };

  const handleRemove = async (memberId: string) => {
    if (!tenantId) {
      throw new Error("No tenant context");
    }
    removeMemberMutation.mutate(memberId);
  };

  const handleSendInvitation = async (data: SendInvitationInput) => {
    // TODO: SDK does not yet have invitation endpoints
    console.log("Send invitation not yet implemented in SDK", data);
    toast({
      title: "Not available",
      description: "Invitation functionality is not yet available",
      variant: "destructive",
    });
    throw new Error("Invitation functionality not yet available");
  };

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Members" description="Manage team members" />
        <Card>
          <CardContent className="pt-6">
            <div className="flex flex-col items-center justify-center text-center space-y-4">
              <AlertCircle className="h-12 w-12 text-destructive" />
              <div>
                <p className="font-medium text-destructive">Error loading members</p>
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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <PageHeader
          title="Members"
          description="Manage team members and their roles"
        />
        <InvitationForm
          onSubmit={handleSendInvitation}
          trigger={
            <Button>
              <UserPlus className="h-4 w-4 mr-2" />
              Invite Member
            </Button>
          }
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Users className="h-5 w-5" />
            Team Members
          </CardTitle>
          <CardDescription>
            {isLoading || authLoading ? (
              <Skeleton className="h-4 w-48" />
            ) : (
              `${members.length} member${members.length !== 1 ? "s" : ""} in your tenant`
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
          ) : members.length === 0 ? (
            <div className="text-center py-12">
              <Users className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
              <p className="text-lg font-medium">No members yet</p>
              <p className="text-sm text-muted-foreground mt-1">
                Invite team members to collaborate
              </p>
            </div>
          ) : (
            <MemberTable
              members={members}
              onRoleChange={handleRoleChange}
              onRemove={handleRemove}
              isLoading={isLoading}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
