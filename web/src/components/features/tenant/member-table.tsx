"use client";

import * as React from "react";
import { Crown, MoreHorizontal, Shield, Trash2, User, Eye } from "lucide-react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "@/components/ui/data-table";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { MemberRoleEditor } from "./member-role-editor";
import type { Member, TenantRole } from "@/types/tenant";

interface MemberTableProps {
  members: Member[];
  onRoleChange: (memberId: string, role: TenantRole) => Promise<void>;
  onRemove: (memberId: string) => Promise<void>;
  isLoading?: boolean;
}

const roleIcons: Record<TenantRole, typeof Crown> = {
  owner: Crown,
  admin: Shield,
  member: User,
  viewer: Eye,
};

const roleColors: Record<TenantRole, "default" | "secondary" | "outline"> = {
  owner: "default",
  admin: "secondary",
  member: "outline",
  viewer: "outline",
};

export function MemberTable({
  members,
  onRoleChange,
  onRemove,
  isLoading,
}: MemberTableProps) {
  const [processingId, setProcessingId] = React.useState<string | null>(null);

  const handleRoleChange = async (memberId: string, role: TenantRole) => {
    setProcessingId(memberId);
    try {
      await onRoleChange(memberId, role);
    } catch (error) {
      console.error("Failed to update role:", error);
    } finally {
      setProcessingId(null);
    }
  };

  const handleRemove = async (memberId: string) => {
    if (!confirm("Are you sure you want to remove this member?")) return;

    setProcessingId(memberId);
    try {
      await onRemove(memberId);
    } catch (error) {
      console.error("Failed to remove member:", error);
    } finally {
      setProcessingId(null);
    }
  };

  const columns: ColumnDef<Member>[] = [
    {
      accessorKey: "user",
      header: "Member",
      cell: ({ row }) => {
        const user = row.original.user;
        const initials = user.name
          .split(" ")
          .map((n) => n[0])
          .join("")
          .toUpperCase();

        return (
          <div className="flex items-center gap-3">
            <Avatar className="h-8 w-8">
              <AvatarImage src={user.avatarUrl} alt={user.name} />
              <AvatarFallback>{initials}</AvatarFallback>
            </Avatar>
            <div className="flex flex-col">
              <span className="font-medium">{user.name}</span>
              <span className="text-sm text-muted-foreground">
                {user.email}
              </span>
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: "role",
      header: "Role",
      cell: ({ row }) => {
        const role = row.original.role;
        const Icon = roleIcons[role];
        const isProcessing = processingId === row.original.id;

        return (
          <MemberRoleEditor
            currentRole={role}
            disabled={isProcessing || isLoading}
            onRoleChange={(newRole) => handleRoleChange(row.original.id, newRole)}
          />
        );
      },
    },
    {
      accessorKey: "joinedAt",
      header: "Joined",
      cell: ({ row }) => {
        const date = new Date(row.original.joinedAt);
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
      id: "actions",
      cell: ({ row }) => {
        const member = row.original;
        const isProcessing = processingId === member.id;

        return (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="ghost"
                className="h-8 w-8 p-0"
                disabled={isProcessing || isLoading}
              >
                <span className="sr-only">Open menu</span>
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>Actions</DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onClick={() => handleRemove(member.id)}
                className="text-destructive focus:text-destructive"
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Remove Member
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        );
      },
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={members}
      searchKey="user"
      searchPlaceholder="Search members..."
    />
  );
}
