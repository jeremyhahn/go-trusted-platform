'use client';

/**
 * Applications List Page
 *
 * Displays all OAuth applications in a searchable table with actions.
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
import { Plus, AppWindow, AlertCircle, Loader2 } from 'lucide-react';

/**
 * UI representation of an application for display purposes
 */
interface DisplayApplication {
  clientId: string;
  name: string;
  redirectUriCount: number;
  grantTypes: string[];
  resourcePrefix?: string;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Applications list page component
 */
export default function AppsPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { user: authUser, tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();

  // Fetch applications using SDK
  const {
    data: appsData,
    isLoading: appsLoading,
    error: appsError,
    refetch: refetchApps,
  } = useApi(
    () => tenantId ? iam.listApps({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading applications',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK apps to DisplayApplication for UI compatibility
  const apps: DisplayApplication[] = useMemo(() => {
    if (!appsData?.apps) return [];
    return appsData.apps.map((app) => ({
      clientId: app.clientId,
      name: app.name || app.clientId,
      redirectUriCount: app.redirectUris?.length || 0,
      grantTypes: app.grantTypes || [],
      resourcePrefix: app.resourcePrefix,
      createdAt: app.createdAt,
      updatedAt: app.updatedAt,
    }));
  }, [appsData]);

  // Delete app mutation
  const deleteAppMutation = useMutation(
    async (clientId: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.deleteApp(tenantId, clientId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Application deleted',
          description: 'The application has been deleted successfully',
          variant: 'success',
        });
        refetchApps();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting application',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleView = useCallback((app: DisplayApplication) => {
    router.push(`/iam/apps/${app.clientId}`);
  }, [router]);

  const handleEdit = useCallback((app: DisplayApplication) => {
    router.push(`/iam/apps/${app.clientId}`);
  }, [router]);

  const handleDelete = useCallback((app: DisplayApplication) => {
    if (window.confirm(`Are you sure you want to delete "${app.name}"?`)) {
      deleteAppMutation.mutate(app.clientId);
    }
  }, [deleteAppMutation]);

  const handleBulkDelete = useCallback(async (appsToDelete: DisplayApplication[]) => {
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
        `Are you sure you want to delete ${appsToDelete.length} application(s)?`
      )
    ) {
      try {
        await Promise.all(
          appsToDelete.map((app) => iam.deleteApp(tenantId, app.clientId))
        );
        toast({
          title: 'Applications deleted',
          description: `${appsToDelete.length} application(s) have been deleted successfully`,
          variant: 'success',
        });
        refetchApps();
      } catch {
        toast({
          title: 'Error deleting applications',
          description: 'Some applications could not be deleted',
          variant: 'destructive',
        });
      }
    }
  }, [tenantId, iam, toast, refetchApps]);

  const columns: ColumnDef<DisplayApplication>[] = useMemo(() => [
    createSelectColumn<DisplayApplication>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Application Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <AppWindow className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: 'clientId',
      header: 'Client ID',
      cell: ({ row }) => (
        <code className="text-xs bg-muted px-2 py-1 rounded">
          {row.original.clientId.slice(0, 16)}...
        </code>
      ),
    },
    {
      accessorKey: 'grantTypes',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Grant Types" />
      ),
      cell: ({ row }) => (
        <div className="flex flex-wrap gap-1">
          {row.original.grantTypes.slice(0, 2).map((grant) => (
            <Badge key={grant} variant="outline" className="text-xs">
              {grant.replace('_', ' ')}
            </Badge>
          ))}
          {row.original.grantTypes.length > 2 && (
            <Badge variant="secondary" className="text-xs">
              +{row.original.grantTypes.length - 2}
            </Badge>
          )}
        </div>
      ),
    },
    {
      accessorKey: 'redirectUriCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Redirect URIs" />
      ),
      cell: ({ row }) => (
        <span className="text-sm">{row.original.redirectUriCount}</span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => {
        const app = row.original;
        return (
          <DataTableRowActions
            row={app}
            actions={[
              {
                label: 'View',
                onClick: () => handleView(app),
              },
              {
                label: 'Edit',
                onClick: () => handleEdit(app),
              },
              {
                label: 'Rotate Secret',
                onClick: () => {
                  toast({
                    title: 'Feature coming soon',
                    description: 'Secret rotation will be available in a future update',
                  });
                },
                separator: true,
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(app),
                variant: 'destructive',
              },
            ]}
          />
        );
      },
    },
  ], [handleView, handleEdit, handleDelete, toast]);

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

  if (appsError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Applications</AlertTitle>
          <AlertDescription>
            {appsError.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetchApps()}
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
          <h1 className="text-3xl font-bold tracking-tight">Applications</h1>
          <p className="text-muted-foreground">
            Manage OAuth client applications and their configurations
          </p>
        </div>
        <Button onClick={() => router.push('/iam/apps/new')}>
          <Plus className="mr-2 h-4 w-4" />
          Register Application
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Applications</CardTitle>
            <AppWindow className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{apps?.length || 0}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">With Redirect URIs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {apps?.filter((a) => a.redirectUriCount > 0).length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Redirect URIs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {apps?.reduce((sum, app) => sum + app.redirectUriCount, 0) || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Applications Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable
            columns={columns}
            data={apps || []}
            searchKey="name"
            searchPlaceholder="Search applications..."
            loading={appsLoading}
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
