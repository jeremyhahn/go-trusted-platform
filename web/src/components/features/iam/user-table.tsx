'use client';

/**
 * User Table Component
 *
 * Displays users in a sortable, filterable DataTable with actions.
 */

import React from 'react';
import { ColumnDef } from '@tanstack/react-table';
import { LegacyUser, UserStatus } from '@/types/iam';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Avatar } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { formatDistanceToNow } from 'date-fns';

interface UserTableProps {
  users: LegacyUser[];
  loading?: boolean;
  onView?: (user: LegacyUser) => void;
  onEdit?: (user: LegacyUser) => void;
  onDisable?: (user: LegacyUser) => void;
  onDelete?: (user: LegacyUser) => void;
  onBulkDelete?: (users: LegacyUser[]) => void;
}

// Status badge mapping
const statusVariants: Record<UserStatus, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  active: 'default',
  disabled: 'destructive',
  pending: 'secondary',
};

/**
 * User table columns definition
 */
export function createUserColumns(
  onView?: (user: LegacyUser) => void,
  onEdit?: (user: LegacyUser) => void,
  onDisable?: (user: LegacyUser) => void,
  onDelete?: (user: LegacyUser) => void
): ColumnDef<LegacyUser>[] {
  return [
    createSelectColumn<LegacyUser>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="User" />
      ),
      cell: ({ row }) => {
        const user = row.original;
        return (
          <div className="flex items-center gap-3">
            <Avatar className="h-8 w-8">
              {user.avatarUrl ? (
                <img src={user.avatarUrl} alt={user.name} />
              ) : (
                <div className="flex h-full w-full items-center justify-center bg-primary text-primary-foreground text-sm font-medium">
                  {user.name.charAt(0).toUpperCase()}
                </div>
              )}
            </Avatar>
            <div className="flex flex-col">
              <span className="font-medium">{user.name}</span>
              <span className="text-sm text-muted-foreground">{user.email}</span>
            </div>
          </div>
        );
      },
    },
    {
      accessorKey: 'roles',
      header: 'Roles',
      cell: ({ row }) => {
        const roles = row.original.roles;
        if (!roles || roles.length === 0) {
          return <span className="text-muted-foreground text-sm">No roles</span>;
        }
        return (
          <div className="flex flex-wrap gap-1">
            {roles.slice(0, 3).map((role) => (
              <Badge key={role.id} variant="outline">
                {role.name}
              </Badge>
            ))}
            {roles.length > 3 && (
              <Badge variant="outline">+{roles.length - 3}</Badge>
            )}
          </div>
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: 'status',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => {
        const status = row.original.status;
        return (
          <Badge variant={statusVariants[status]}>
            {status.charAt(0).toUpperCase() + status.slice(1)}
          </Badge>
        );
      },
    },
    {
      accessorKey: 'createdAt',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Created" />
      ),
      cell: ({ row }) => {
        const date = new Date(row.original.createdAt);
        return (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(date, { addSuffix: true })}
          </span>
        );
      },
    },
    {
      accessorKey: 'lastLoginAt',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Last Login" />
      ),
      cell: ({ row }) => {
        const lastLogin = row.original.lastLoginAt;
        if (!lastLogin) {
          return <span className="text-sm text-muted-foreground">Never</span>;
        }
        const date = new Date(lastLogin);
        return (
          <span className="text-sm text-muted-foreground">
            {formatDistanceToNow(date, { addSuffix: true })}
          </span>
        );
      },
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const user = row.original;
        const actions = [];

        if (onView) {
          actions.push({
            label: 'View',
            onClick: () => onView(user),
          });
        }

        if (onEdit) {
          actions.push({
            label: 'Edit',
            onClick: () => onEdit(user),
          });
        }

        if (onDisable && user.status === 'active') {
          actions.push({
            label: 'Disable',
            onClick: () => onDisable(user),
            separator: true,
          });
        }

        if (onDisable && user.status === 'disabled') {
          actions.push({
            label: 'Enable',
            onClick: () => onDisable(user),
            separator: true,
          });
        }

        if (onDelete) {
          actions.push({
            label: 'Delete',
            onClick: () => onDelete(user),
            variant: 'destructive' as const,
            separator: actions.length > 0,
          });
        }

        return <DataTableRowActions row={user} actions={actions} />;
      },
    },
  ];
}

/**
 * User table component with built-in filtering and actions
 */
export function UserTable({
  users,
  loading = false,
  onView,
  onEdit,
  onDisable,
  onDelete,
  onBulkDelete,
}: UserTableProps) {
  const columns = React.useMemo(
    () => createUserColumns(onView, onEdit, onDisable, onDelete),
    [onView, onEdit, onDisable, onDelete]
  );

  const bulkActions = React.useMemo(() => {
    const actions = [];
    if (onBulkDelete) {
      actions.push({
        label: 'Delete selected',
        onClick: onBulkDelete,
        variant: 'destructive' as const,
      });
    }
    return actions;
  }, [onBulkDelete]);

  return (
    <DataTable
      columns={columns}
      data={users}
      searchKey="name"
      searchPlaceholder="Search users..."
      filterableColumns={[
        {
          id: 'status',
          title: 'Status',
          options: [
            { label: 'Active', value: 'active' },
            { label: 'Disabled', value: 'disabled' },
            { label: 'Pending', value: 'pending' },
          ],
        },
      ]}
      bulkActions={bulkActions}
      loading={loading}
      pagination
      pageSize={25}
      onRowClick={onView}
    />
  );
}
