'use client';

/**
 * Roles List Page
 *
 * Displays all roles in a searchable table with actions.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { ColumnDef } from '@tanstack/react-table';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import type { LegacyRole } from '@/types/iam';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Plus, Shield, AlertCircle, Loader2 } from 'lucide-react';

/**
 * Roles list page component
 */
export default function RolesPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { user: authUser, tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();

  // Fetch roles using SDK
  const {
    data: rolesData,
    isLoading: rolesLoading,
    error: rolesError,
    refetch: refetchRoles,
  } = useApi(
    () => tenantId ? iam.listRoles({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading roles',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK roles to LegacyRole for UI compatibility
  const roles: LegacyRole[] = useMemo(() => {
    if (!rolesData?.roles) return [];
    return rolesData.roles.map((role) => ({
      id: role.id,
      name: role.name || role.id,
      description: role.description || '',
      permissions: (role.permissions || []).map((p) => ({
        id: p,
        name: p,
        resource: p.split(':')[0] || p,
        action: p.split(':')[1] || '*',
        description: '',
      })),
      userCount: 0, // Not provided by backend
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    }));
  }, [rolesData]);

  // Delete role mutation
  const deleteRoleMutation = useMutation(
    async (roleId: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.deleteRole(tenantId, roleId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Role deleted',
          description: 'The role has been deleted successfully',
          variant: 'success',
        });
        refetchRoles();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting role',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleView = useCallback((role: LegacyRole) => {
    router.push(`/iam/roles/${role.id}`);
  }, [router]);

  const handleEdit = useCallback((role: LegacyRole) => {
    router.push(`/iam/roles/${role.id}`);
  }, [router]);

  const handleDelete = useCallback((role: LegacyRole) => {
    if (window.confirm(`Are you sure you want to delete ${role.name}?`)) {
      deleteRoleMutation.mutate(role.id);
    }
  }, [deleteRoleMutation]);

  const handleBulkDelete = useCallback(async (rolesToDelete: LegacyRole[]) => {
    if (!tenantId) {
      toast({
        title: 'Error',
        description: 'No tenant ID available',
        variant: 'destructive',
      });
      return;
    }

    if (
      window.confirm(
        `Are you sure you want to delete ${rolesToDelete.length} role(s)?`
      )
    ) {
      try {
        await Promise.all(
          rolesToDelete.map((role) => iam.deleteRole(tenantId, role.id))
        );
        toast({
          title: 'Roles deleted',
          description: `${rolesToDelete.length} role(s) have been deleted successfully`,
          variant: 'success',
        });
        refetchRoles();
      } catch {
        toast({
          title: 'Error deleting roles',
          description: 'Some roles could not be deleted',
          variant: 'destructive',
        });
      }
    }
  }, [tenantId, iam, toast, refetchRoles]);

  const columns: ColumnDef<LegacyRole>[] = useMemo(() => [
    createSelectColumn<LegacyRole>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Role Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {row.original.description || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'userCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Users" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.userCount}</span>
      ),
    },
    {
      accessorKey: 'permissions',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Permissions" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.permissions.length}</span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const role = row.original;
        return (
          <DataTableRowActions
            row={role}
            actions={[
              {
                label: 'View',
                onClick: () => handleView(role),
              },
              {
                label: 'Edit',
                onClick: () => handleEdit(role),
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(role),
                variant: 'destructive',
                separator: true,
              },
            ]}
          />
        );
      },
    },
  ], [handleView, handleEdit, handleDelete]);

  // Show auth loading state
  if (authLoading) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading authentication...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show tenant error
  if (!tenantId) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Authentication Required</AlertTitle>
          <AlertDescription>
            No tenant ID available. Please log in again to access IAM management.
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (rolesError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Roles</AlertTitle>
          <AlertDescription>
            {rolesError.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetchRoles()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-1">
          <h1 className="text-3xl font-bold tracking-tight">Roles</h1>
          <p className="text-muted-foreground">
            Manage roles and their permissions
          </p>
        </div>
        <Button onClick={() => router.push('/iam/roles/new')}>
          <Plus className="mr-2 h-4 w-4" />
          Add Role
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Roles</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{roles?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {roles?.reduce((sum, role) => sum + role.userCount, 0) || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Permissions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {roles?.reduce(
                (sum, role) => sum + role.permissions.length,
                0
              ) || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Roles Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable
            columns={columns}
            data={roles || []}
            searchKey="name"
            searchPlaceholder="Search roles..."
            loading={rolesLoading}
            pagination
            pageSize={25}
            onRowClick={handleView}
            bulkActions={[
              {
                label: 'Delete selected',
                onClick: handleBulkDelete,
                variant: 'destructive',
              },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}
