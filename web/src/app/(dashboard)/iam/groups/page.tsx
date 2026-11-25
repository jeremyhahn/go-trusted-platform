'use client';

/**
 * Groups List Page
 *
 * Displays all groups in a searchable table with actions.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { ColumnDef } from '@tanstack/react-table';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { useCapabilities } from '@/hooks/use-capabilities';
import { Gated } from '@/components/features/capabilities/gated';
import { useAuth } from '@/contexts/AuthContext';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Plus, Users2, AlertCircle, Loader2 } from 'lucide-react';

/**
 * UI representation of a group for display purposes
 */
interface DisplayGroup {
  id: string;
  name: string;
  description: string;
  memberCount: number;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Groups list page component
 */
export default function GroupsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();
  const { loading: capsLoading, capability } = useCapabilities();
  const listCap = capability('GET /api/v1/iam/tenants/{tenant}/groups');
  const updateCap = capability('PUT /api/v1/iam/tenants/{tenant}/groups/{id}');
  const deleteCap = capability('DELETE /api/v1/iam/tenants/{tenant}/groups/{id}');

  // Fetch groups using SDK, once the server says it offers the list
  const {
    data: groupsData,
    isLoading: groupsLoading,
    error: groupsError,
    refetch: refetchGroups,
  } = useApi(
    () => tenantId && listCap.enabled ? iam.listGroups({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId, listCap.enabled],
    {
      enabled: !capsLoading && listCap.enabled,
      onError: (err) => {
        toast({
          title: 'Error loading groups',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK groups to DisplayGroup for UI compatibility
  const groups: DisplayGroup[] = useMemo(() => {
    if (!groupsData?.groups) return [];
    return groupsData.groups.map((group) => ({
      id: group.id,
      name: group.name || group.id,
      description: group.description || '',
      memberCount: group.members?.length || 0,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
    }));
  }, [groupsData]);

  // Delete group mutation
  const deleteGroupMutation = useMutation(
    async (groupId: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.deleteGroup(tenantId, groupId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Group deleted',
          description: 'The group has been deleted successfully',
          variant: 'success',
        });
        refetchGroups();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting group',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleView = useCallback((group: DisplayGroup) => {
    router.push(`/iam/groups/${group.id}`);
  }, [router]);

  const handleEdit = useCallback((group: DisplayGroup) => {
    router.push(`/iam/groups/${group.id}`);
  }, [router]);

  const handleDelete = useCallback((group: DisplayGroup) => {
    if (window.confirm(`Are you sure you want to delete ${group.name}?`)) {
      deleteGroupMutation.mutate(group.id);
    }
  }, [deleteGroupMutation]);

  const handleBulkDelete = useCallback(async (groupsToDelete: DisplayGroup[]) => {
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
        `Are you sure you want to delete ${groupsToDelete.length} group(s)?`
      )
    ) {
      try {
        await Promise.all(
          groupsToDelete.map((group) => iam.deleteGroup(tenantId, group.id))
        );
        toast({
          title: 'Groups deleted',
          description: `${groupsToDelete.length} group(s) have been deleted successfully`,
          variant: 'success',
        });
        refetchGroups();
      } catch {
        toast({
          title: 'Error deleting groups',
          description: 'Some groups could not be deleted',
          variant: 'destructive',
        });
      }
    }
  }, [tenantId, iam, toast, refetchGroups]);

  const columns: ColumnDef<DisplayGroup>[] = useMemo(() => [
    createSelectColumn<DisplayGroup>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Group Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Users2 className="h-4 w-4 text-muted-foreground" />
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
      accessorKey: 'memberCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Members" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.memberCount}</span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const group = row.original;
        return (
          <DataTableRowActions
            row={group}
            actions={[
              {
                label: 'View',
                onClick: () => handleView(group),
              },
              {
                label: 'Edit',
                onClick: () => handleEdit(group),
                disabled: !updateCap.enabled,
                title: updateCap.enabled ? undefined : updateCap.reason,
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(group),
                variant: 'destructive',
                separator: true,
                disabled: !deleteCap.enabled,
                title: deleteCap.enabled ? undefined : deleteCap.reason,
              },
            ]}
          />
        );
      },
    },
  ], [handleView, handleEdit, handleDelete, updateCap, deleteCap]);

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

  if (!capsLoading && !listCap.enabled) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        <div className="space-y-1">
          <h1 className="text-3xl font-bold tracking-tight">Groups</h1>
          <p className="text-muted-foreground">
            Manage user groups and their memberships
          </p>
        </div>
        <Card data-testid="iam-groups-not-enabled">
          <CardHeader>
            <CardTitle>Groups are not enabled on this server</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">{listCap.reason}</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (groupsError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Groups</AlertTitle>
          <AlertDescription>
            {groupsError.message}
            <Gated op="GET /api/v1/iam/tenants/{tenant}/groups">
              <Button
                variant="outline"
                size="sm"
                className="ml-4"
                onClick={() => refetchGroups()}
              >
                Retry
              </Button>
            </Gated>
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
          <h1 className="text-3xl font-bold tracking-tight">Groups</h1>
          <p className="text-muted-foreground">
            Manage user groups and their memberships
          </p>
        </div>
        <Gated op="POST /api/v1/iam/tenants/{tenant}/groups">
          <Button onClick={() => router.push('/iam/groups/new')}>
            <Plus className="mr-2 h-4 w-4" />
            Add Group
          </Button>
        </Gated>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Groups</CardTitle>
            <Users2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{groups?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Members</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {groups?.reduce((sum, group) => sum + group.memberCount, 0) || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Empty Groups</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {groups?.filter((g) => g.memberCount === 0).length || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Groups Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable
            columns={columns}
            data={groups || []}
            searchKey="name"
            searchPlaceholder="Search groups..."
            loading={capsLoading || groupsLoading}
            pagination
            pageSize={25}
            onRowClick={handleView}
            bulkActions={[
              {
                label: 'Delete selected',
                onClick: handleBulkDelete,
                variant: 'destructive',
                disabled: !deleteCap.enabled,
                title: deleteCap.enabled ? undefined : deleteCap.reason,
              },
            ]}
          />
        </CardContent>
      </Card>
    </div>
  );
}
