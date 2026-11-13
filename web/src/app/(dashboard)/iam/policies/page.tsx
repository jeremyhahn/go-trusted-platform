'use client';

/**
 * Policies List Page
 *
 * Displays all policies in a searchable table with actions.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { ColumnDef } from '@tanstack/react-table';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Plus, FileCheck, AlertCircle, Loader2 } from 'lucide-react';

/**
 * UI representation of a policy for display purposes
 */
interface DisplayPolicy {
  name: string;
  description: string;
  priority: number;
  labelCount: number;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Get priority badge variant based on priority level
 */
function getPriorityVariant(priority: number): 'default' | 'secondary' | 'destructive' | 'outline' {
  if (priority <= 10) return 'destructive';
  if (priority <= 50) return 'default';
  if (priority <= 100) return 'secondary';
  return 'outline';
}

/**
 * Policies list page component
 */
export default function PoliciesPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();

  // Fetch policies using SDK
  const {
    data: policiesData,
    isLoading: policiesLoading,
    error: policiesError,
    refetch: refetchPolicies,
  } = useApi(
    () => tenantId ? iam.listPolicies({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading policies',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK policies to DisplayPolicy for UI compatibility
  const policies: DisplayPolicy[] = useMemo(() => {
    if (!policiesData?.policies) return [];
    return policiesData.policies.map((policy) => ({
      name: policy.name,
      description: policy.description || '',
      priority: policy.priority,
      labelCount: policy.labels ? Object.keys(policy.labels).length : 0,
      createdAt: policy.createdAt,
      updatedAt: policy.updatedAt,
    }));
  }, [policiesData]);

  // Delete policy mutation
  const deletePolicyMutation = useMutation(
    async (policyName: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.deletePolicy(tenantId, policyName);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Policy deleted',
          description: 'The policy has been deleted successfully',
          variant: 'success',
        });
        refetchPolicies();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting policy',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleView = useCallback((policy: DisplayPolicy) => {
    router.push(`/iam/policies/${encodeURIComponent(policy.name)}`);
  }, [router]);

  const handleEdit = useCallback((policy: DisplayPolicy) => {
    router.push(`/iam/policies/${encodeURIComponent(policy.name)}`);
  }, [router]);

  const handleDelete = useCallback((policy: DisplayPolicy) => {
    if (window.confirm(`Are you sure you want to delete policy "${policy.name}"?`)) {
      deletePolicyMutation.mutate(policy.name);
    }
  }, [deletePolicyMutation]);

  const handleBulkDelete = useCallback(async (policiesToDelete: DisplayPolicy[]) => {
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
        `Are you sure you want to delete ${policiesToDelete.length} policy(ies)?`
      )
    ) {
      try {
        await Promise.all(
          policiesToDelete.map((policy) => iam.deletePolicy(tenantId, policy.name))
        );
        toast({
          title: 'Policies deleted',
          description: `${policiesToDelete.length} policy(ies) have been deleted successfully`,
          variant: 'success',
        });
        refetchPolicies();
      } catch {
        toast({
          title: 'Error deleting policies',
          description: 'Some policies could not be deleted',
          variant: 'destructive',
        });
      }
    }
  }, [tenantId, iam, toast, refetchPolicies]);

  const columns: ColumnDef<DisplayPolicy>[] = useMemo(() => [
    createSelectColumn<DisplayPolicy>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Policy Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <FileCheck className="h-4 w-4 text-muted-foreground" />
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
      accessorKey: 'priority',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Priority" />
      ),
      cell: ({ row }) => (
        <Badge variant={getPriorityVariant(row.original.priority)}>
          {row.original.priority}
        </Badge>
      ),
    },
    {
      accessorKey: 'labelCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Labels" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.labelCount}</span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const policy = row.original;
        return (
          <DataTableRowActions
            row={policy}
            actions={[
              {
                label: 'View',
                onClick: () => handleView(policy),
              },
              {
                label: 'Edit',
                onClick: () => handleEdit(policy),
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(policy),
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

  if (policiesError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Policies</AlertTitle>
          <AlertDescription>
            {policiesError.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetchPolicies()}
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
          <h1 className="text-3xl font-bold tracking-tight">Policies</h1>
          <p className="text-muted-foreground">
            Manage access control policies and authorization rules
          </p>
        </div>
        <Button onClick={() => router.push('/iam/policies/new')}>
          <Plus className="mr-2 h-4 w-4" />
          Add Policy
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Policies</CardTitle>
            <FileCheck className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{policies?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">High Priority</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {policies?.filter((p) => p.priority <= 10).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">With Labels</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {policies?.filter((p) => p.labelCount > 0).length || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Policies Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable
            columns={columns}
            data={policies || []}
            searchKey="name"
            searchPlaceholder="Search policies..."
            loading={policiesLoading}
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
