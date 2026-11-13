'use client';

/**
 * API Tokens Page
 *
 * Displays and manages API tokens with generation and revocation.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useState, useMemo, useCallback } from 'react';
import { ColumnDef } from '@tanstack/react-table';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Plus, Key, Clock, AlertCircle, Loader2, Copy, Check } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

/**
 * Display type for applications used as API tokens
 */
interface DisplayApplication {
  clientId: string;
  name: string;
  grantTypes: string[];
  createdAt?: string;
}

/**
 * API Tokens page component
 */
export default function TokensPage() {
  const { toast } = useToast();
  const { tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [displaySecret, setDisplaySecret] = useState<{
    clientId: string;
    clientSecret: string;
    name: string;
  } | null>(null);
  const [newAppName, setNewAppName] = useState('');
  const [copied, setCopied] = useState(false);

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
      grantTypes: app.grantTypes || [],
      createdAt: app.createdAt,
    }));
  }, [appsData]);

  // Register app mutation
  const registerAppMutation = useMutation(
    async (data: { name: string; grantTypes: string[] }) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.registerApp({
        tenantId,
        name: data.name,
        grantTypes: data.grantTypes,
        redirectUris: [],
        responseTypes: [],
      });
    },
    {
      onSuccess: (result) => {
        toast({
          title: 'Application registered',
          description: 'Your application has been registered successfully',
          variant: 'success',
        });
        refetchApps();
        setIsFormOpen(false);
        setNewAppName('');
        // Show the client secret in the display dialog
        const app = result?.app;
        if (app?.clientSecret) {
          setDisplaySecret({
            clientId: app.clientId,
            clientSecret: app.clientSecret,
            name: app.name,
          });
        }
      },
      onError: (error) => {
        toast({
          title: 'Error registering application',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

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

  // Rotate secret mutation
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

  const handleDelete = useCallback((app: DisplayApplication) => {
    if (window.confirm(`Are you sure you want to delete "${app.name}"?`)) {
      deleteAppMutation.mutate(app.clientId);
    }
  }, [deleteAppMutation]);

  const handleRotateSecret = useCallback((app: DisplayApplication) => {
    if (
      window.confirm(
        `Are you sure you want to rotate the secret for "${app.name}"? The old secret will stop working immediately.`
      )
    ) {
      rotateSecretMutation.mutate(app.clientId);
    }
  }, [rotateSecretMutation]);

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

  const handleCreateApp = () => {
    if (!newAppName.trim()) {
      toast({
        title: 'Validation error',
        description: 'Application name is required',
        variant: 'destructive',
      });
      return;
    }
    registerAppMutation.mutate({
      name: newAppName.trim(),
      grantTypes: ['client_credentials'],
    });
  };

  const handleCopySecret = async () => {
    if (displaySecret?.clientSecret) {
      await navigator.clipboard.writeText(displaySecret.clientSecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const columns: ColumnDef<DisplayApplication>[] = useMemo(() => [
    createSelectColumn<DisplayApplication>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Application Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Key className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.name}</span>
        </div>
      ),
    },
    {
      accessorKey: 'clientId',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Client ID" />
      ),
      cell: ({ row }) => (
        <code className="text-xs bg-muted px-2 py-1 rounded">
          {row.original.clientId}
        </code>
      ),
    },
    {
      accessorKey: 'grantTypes',
      header: 'Grant Types',
      cell: ({ row }) => {
        const grantTypes = row.original.grantTypes || [];
        return (
          <div className="flex flex-wrap gap-1">
            {grantTypes.slice(0, 2).map((type) => (
              <Badge key={type} variant="outline" className="text-xs">
                {type}
              </Badge>
            ))}
            {grantTypes.length > 2 && (
              <Badge variant="outline" className="text-xs">
                +{grantTypes.length - 2}
              </Badge>
            )}
          </div>
        );
      },
      enableSorting: false,
    },
    {
      accessorKey: 'createdAt',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Created" />
      ),
      cell: ({ row }) => {
        const createdAt = row.original.createdAt;
        if (!createdAt) {
          return <span className="text-sm text-muted-foreground">-</span>;
        }
        const date = new Date(createdAt);
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
        const app = row.original;
        return (
          <DataTableRowActions
            row={app}
            actions={[
              {
                label: 'Rotate Secret',
                onClick: () => handleRotateSecret(app),
              },
              {
                label: 'Delete',
                onClick: () => handleDelete(app),
                variant: 'destructive',
                separator: true,
              },
            ]}
          />
        );
      },
    },
  ], [handleRotateSecret, handleDelete]);

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
            No tenant ID available. Please log in again to access API credentials.
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
          <h1 className="text-3xl font-bold tracking-tight">API Credentials</h1>
          <p className="text-muted-foreground">
            Manage OAuth applications for programmatic API access
          </p>
        </div>
        <Button onClick={() => setIsFormOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Register Application
        </Button>
      </div>

      {/* Info Alert */}
      <Alert>
        <Key className="h-4 w-4" />
        <AlertTitle>OAuth Client Credentials</AlertTitle>
        <AlertDescription>
          Applications use OAuth 2.0 client credentials flow for API access.
          Each application receives a client ID and secret that can be used to
          obtain access tokens.
        </AlertDescription>
      </Alert>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Applications</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{apps.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{apps.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Grant Types</CardTitle>
            <Clock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {new Set(apps.flatMap((a) => a.grantTypes || [])).size}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Applications Table */}
      <Card>
        <CardContent className="pt-6">
          <DataTable
            columns={columns}
            data={apps}
            searchKey="name"
            searchPlaceholder="Search applications..."
            loading={appsLoading}
            pagination
            pageSize={25}
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

      {/* Register Application Dialog */}
      <Dialog open={isFormOpen} onOpenChange={setIsFormOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register New Application</DialogTitle>
            <DialogDescription>
              Create a new OAuth application to get API credentials.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="name">Application Name</Label>
              <Input
                id="name"
                placeholder="My Application"
                value={newAppName}
                onChange={(e) => setNewAppName(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setIsFormOpen(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreateApp}
              disabled={registerAppMutation.isLoading}
            >
              {registerAppMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Register
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Secret Display Dialog */}
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
              <div className="flex gap-2">
                <code className="flex-1 bg-muted p-2 rounded text-sm break-all">
                  {displaySecret?.clientSecret}
                </code>
                <Button variant="outline" size="icon" onClick={handleCopySecret}>
                  {copied ? (
                    <Check className="h-4 w-4" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
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
