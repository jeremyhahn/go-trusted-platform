'use client';

/**
 * Applications List Page
 *
 * Displays all OAuth applications in a searchable table with actions.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useState, useMemo, useCallback } from 'react';
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';
import { Plus, AppWindow, AlertCircle, Loader2 } from 'lucide-react';
import { Gated } from '@/components/features/capabilities/gated';
import { useCapabilities } from '@/hooks/use-capabilities';

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
  const { tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();
  const { capability } = useCapabilities();
  const deleteCap = capability('DELETE /api/v1/iam/tenants/{tenant}/apps/{id}');
  const rotateCap = capability('POST /api/v1/iam/tenants/{tenant}/apps/{id}/rotate');
  const [displaySecret, setDisplaySecret] = useState<{
    clientId: string;
    clientSecret: string;
    name: string;
  } | null>(null);

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

  // Transform SDK apps to DisplayApplication for UI compatibility. The
  // list reply is the proto ListIAMAppsResponse in protojson (#445):
  // camelCase fields, every list present.
  const apps: DisplayApplication[] = useMemo(() => {
    return (appsData?.apps ?? []).map((app) => {
      const clientId = app.clientId ?? '';
      return {
        clientId,
        name: app.name || clientId || 'unnamed',
        redirectUriCount: app.redirectUris?.length ?? 0,
        grantTypes: app.grantTypes ?? [],
        resourcePrefix: app.resourcePrefix,
        createdAt: app.createdAt,
        updatedAt: app.updatedAt,
      };
    });
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
    if (!deleteCap.enabled) return;
    if (window.confirm(`Are you sure you want to delete "${app.name}"?`)) {
      deleteAppMutation.mutate(app.clientId);
    }
  }, [deleteAppMutation, deleteCap.enabled]);

  // Rotate secret mutation: the new secret is shown once in the dialog.
  const rotateSecretMutation = useMutation(
    async (clientId: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.rotateAppSecret(tenantId, clientId);
    },
    {
      onSuccess: (result) => {
        toast({
          title: 'Secret rotated',
          description: 'The application secret has been rotated successfully',
          variant: 'success',
        });
        if (result) {
          setDisplaySecret({
            clientId: result.clientId,
            clientSecret: result.clientSecret,
            name: result.name,
          });
        }
      },
      onError: (error) => {
        toast({
          title: 'Error rotating secret',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleRotateSecret = useCallback((app: DisplayApplication) => {
    if (!rotateCap.enabled) return;
    if (
      window.confirm(
        `Are you sure you want to rotate the secret for "${app.name}"? The old secret will stop working immediately.`
      )
    ) {
      rotateSecretMutation.mutate(app.clientId);
    }
  }, [rotateSecretMutation, rotateCap.enabled]);

  const handleBulkDelete = useCallback(async (appsToDelete: DisplayApplication[]) => {
    if (!deleteCap.enabled) return;
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
  }, [tenantId, iam, toast, refetchApps, deleteCap.enabled]);

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
      cell: ({ row }) => {
        const id = row.original.clientId || '';
        return (
          <code className="text-xs bg-muted px-2 py-1 rounded">
            {id.length > 16 ? id.slice(0, 16) + '...' : id || '—'}
          </code>
        );
      },
    },
    {
      accessorKey: 'grantTypes',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Grant Types" />
      ),
      cell: ({ row }) => {
        const grants = row.original.grantTypes || [];
        return (
          <div className="flex flex-wrap gap-1">
            {grants.slice(0, 2).map((grant) => (
              <Badge key={grant} variant="outline" className="text-xs">
                {grant.replace('_', ' ')}
              </Badge>
            ))}
            {grants.length > 2 && (
              <Badge variant="secondary" className="text-xs">
                +{grants.length - 2}
              </Badge>
            )}
            {grants.length === 0 && <span className="text-xs text-muted-foreground">—</span>}
          </div>
        );
      },
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
                onClick: () => handleRotateSecret(app),
                separator: true,
                disabled: !rotateCap.enabled,
                title: rotateCap.enabled ? undefined : rotateCap.reason,
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(app),
                variant: 'destructive',
                disabled: !deleteCap.enabled,
                title: deleteCap.enabled ? undefined : deleteCap.reason,
              },
            ]}
          />
        );
      },
    },
  ], [
    handleView,
    handleEdit,
    handleDelete,
    handleRotateSecret,
    rotateCap.enabled,
    rotateCap.reason,
    deleteCap.enabled,
    deleteCap.reason,
  ]);

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
        <Gated op="POST /api/v1/iam/tenants/{tenant}/apps">
          <Button onClick={() => router.push('/iam/apps/new')}>
            <Plus className="mr-2 h-4 w-4" />
            Register Application
          </Button>
        </Gated>
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
                disabled: !deleteCap.enabled,
                title: deleteCap.enabled ? undefined : deleteCap.reason,
              },
            ]}
          />
        </CardContent>
      </Card>

      {/* Secret Display Dialog: the rotated secret is shown once */}
      <Dialog
        open={!!displaySecret}
        onOpenChange={(open) => !open && setDisplaySecret(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Application Credentials</DialogTitle>
            <DialogDescription>
              Save these credentials securely. The client secret will not be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label>Application Name</Label>
              <div className="font-medium">{displaySecret?.name}</div>
            </div>
            <div className="space-y-2">
              <Label>Client ID</Label>
              <code className="block bg-muted p-2 rounded text-sm break-all">
                {displaySecret?.clientId}
              </code>
            </div>
            <div className="space-y-2">
              <Label>Client Secret</Label>
              <code className="block bg-muted p-2 rounded text-sm break-all">
                {displaySecret?.clientSecret}
              </code>
            </div>
            <Alert>
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Important</AlertTitle>
              <AlertDescription>
                Store the client secret securely. It will not be displayed again.
                If you lose it, you will need to rotate the secret.
              </AlertDescription>
            </Alert>
          </div>
          <DialogFooter>
            <Button onClick={() => setDisplaySecret(null)}>Close</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
