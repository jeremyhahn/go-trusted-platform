'use client';

/**
 * Permissions / Groups / Policies Page
 *
 * Displays groups and policies for permission management.
 * The backend uses groups for permission grouping and policies for access control.
 * Connects to:
 * - /api/v1/iam/tenants/{tenant}/groups
 * - /api/v1/iam/tenants/{tenant}/policies
 * - /api/v1/iam/tenants/{tenant}/roles (for extracting permission strings)
 */

import React, { useState, useMemo } from 'react';
import { ColumnDef } from '@tanstack/react-table';
import { useAuth } from '@/contexts/AuthContext';
import { useIAM, useApi } from '@/hooks';
import type { Group, Policy, Role, Permission } from '@/types/iam';
import { DataTable } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Shield, Key, FileText, AlertCircle, Loader2, Users } from 'lucide-react';

/**
 * Permissions list page component
 */
export default function PermissionsPage() {
  const { user: authUser, tenantId, isLoading: authLoading } = useAuth();
  const iam = useIAM();


  // Fetch groups using SDK
  const { data: groupsData, isLoading: groupsLoading, error: groupsError } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.listGroups({ tenantId });
    },
    [tenantId]
  );

  // Fetch policies using SDK
  const { data: policiesData, isLoading: policiesLoading, error: policiesError } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.listPolicies({ tenantId });
    },
    [tenantId]
  );

  // Fetch roles using SDK
  const { data: rolesData, isLoading: rolesLoading, error: rolesError } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.listRoles({ tenantId });
    },
    [tenantId]
  );

  // Convert SDK types to legacy types
  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const groups: Group[] = (groupsData?.groups || []).map((g: any) => ({
    id: g.id,
    name: g.name,
    description: g.description,
    members: g.members || [],
    tenant_id: g.tenantId,
    created_at: g.createdAt,
    updated_at: g.updatedAt
  }));

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const policies: Policy[] = (policiesData?.policies || []).map((p: any) => ({
    name: p.name,
    description: p.description,
    priority: p.priority || 0,
    labels: {},
    tenant_id: p.tenantId
  }));

  const roles = rolesData?.roles || [];
  const loading = groupsLoading || policiesLoading || rolesLoading;
  const error = groupsError || policiesError || rolesError;

  // Extract unique permissions from roles — derived, not stored: a setState
  // inside useMemo re-renders on every recompute.
  const permissions = useMemo<Permission[]>(() => {
    const permissionSet = new Set<string>();
    for (const role of roles) {
      for (const p of role.permissions || []) {
        permissionSet.add(p);
      }
    }
    return Array.from(permissionSet).map((p) => ({
      id: p,
      name: p,
      resource: p.split(':')[0] || p,
      action: p.split(':')[1] || '*',
      description: `Permission: ${p}`,
    }));
  }, [roles]);

  // Group permissions by resource
  const groupedPermissions = useMemo(() => {
    const groups = new Map<string, Permission[]>();
    permissions.forEach((permission) => {
      const resource = permission.resource;
      if (!groups.has(resource)) {
        groups.set(resource, []);
      }
      groups.get(resource)!.push(permission);
    });
    return groups;
  }, [permissions]);

  // Groups table columns
  const groupColumns: ColumnDef<Group>[] = [
    {
      accessorKey: 'id',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Group ID" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Users className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.original.id}</span>
        </div>
      ),
    },
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <span className="font-medium">{row.original.name || row.original.id}</span>
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
      accessorKey: 'members',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Members" />
      ),
      cell: ({ row }) => (
        <Badge variant="secondary">
          {row.original.members?.length || 0} members
        </Badge>
      ),
    },
  ];

  // Policies table columns
  const policyColumns: ColumnDef<Policy>[] = [
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Policy Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-muted-foreground" />
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
        <Badge variant="outline">{row.original.priority}</Badge>
      ),
    },
    {
      accessorKey: 'labels',
      header: 'Labels',
      cell: ({ row }) => {
        const labels = row.original.labels || {};
        const labelEntries = Object.entries(labels);
        return (
          <div className="flex flex-wrap gap-1">
            {labelEntries.slice(0, 2).map(([key, value]) => (
              <Badge key={key} variant="secondary" className="text-xs">
                {key}: {value}
              </Badge>
            ))}
            {labelEntries.length > 2 && (
              <Badge variant="secondary" className="text-xs">
                +{labelEntries.length - 2}
              </Badge>
            )}
          </div>
        );
      },
    },
  ];

  // Permissions table columns
  const permissionColumns: ColumnDef<Permission>[] = [
    {
      accessorKey: 'resource',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Resource" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Shield className="h-4 w-4 text-muted-foreground" />
          <Badge variant="outline">{row.original.resource}</Badge>
        </div>
      ),
    },
    {
      accessorKey: 'action',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Action" />
      ),
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.original.action}</span>
      ),
    },
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <span className="font-medium">{row.original.name}</span>
      ),
    },
    {
      accessorKey: 'description',
      header: 'Description',
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {row.original.description}
        </span>
      ),
    },
  ];

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

  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Data</AlertTitle>
          <AlertDescription>
            {error instanceof Error ? error.message : 'Failed to load data'}
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Page Header */}
      <div className="space-y-1">
        <h1 className="text-3xl font-bold tracking-tight">Access Control</h1>
        <p className="text-muted-foreground">
          Manage groups, policies, and view available permissions
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Groups</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{groups.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Policies</CardTitle>
            <FileText className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{policies.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">
              Total Permissions
            </CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{permissions.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Resources</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{groupedPermissions.size}</div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs for Groups, Policies, and Permissions */}
      <Tabs defaultValue="groups" className="space-y-4">
        <TabsList>
          <TabsTrigger value="groups">Groups ({groups.length})</TabsTrigger>
          <TabsTrigger value="policies">Policies ({policies.length})</TabsTrigger>
          <TabsTrigger value="permissions">Permissions ({permissions.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="groups" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Groups</CardTitle>
              <p className="text-sm text-muted-foreground">
                Groups organize users for permission management
              </p>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={groupColumns}
                data={groups}
                searchKey="name"
                searchPlaceholder="Search groups..."
                loading={loading}
                pagination
                pageSize={25}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="policies" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Policies</CardTitle>
              <p className="text-sm text-muted-foreground">
                Policies define access control rules
              </p>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={policyColumns}
                data={policies}
                searchKey="name"
                searchPlaceholder="Search policies..."
                loading={loading}
                pagination
                pageSize={25}
              />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="permissions" className="space-y-4">
          {/* Permissions by Resource */}
          <div className="space-y-4">
            <h2 className="text-xl font-semibold">Permissions by Resource</h2>
            {Array.from(groupedPermissions.entries()).map(
              ([resource, resourcePermissions]) => (
                <Card key={resource}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Shield className="h-5 w-5 text-muted-foreground" />
                        <CardTitle>{resource}</CardTitle>
                        <Badge variant="secondary">
                          {resourcePermissions.length} permission
                          {resourcePermissions.length !== 1 ? 's' : ''}
                        </Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {resourcePermissions.map((permission) => (
                        <div
                          key={permission.id}
                          className="flex items-start gap-3 p-3 border rounded-md"
                        >
                          <Key className="h-4 w-4 mt-1 text-muted-foreground" />
                          <div className="flex-1 space-y-1">
                            <div className="flex items-center gap-2">
                              <p className="font-medium">{permission.name}</p>
                              <Badge variant="outline" className="font-mono text-xs">
                                {permission.action}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">
                              {permission.description}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )
            )}
          </div>

          {/* All Permissions Table */}
          <Card>
            <CardHeader>
              <CardTitle>All Permissions</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable
                columns={permissionColumns}
                data={permissions}
                searchKey="name"
                searchPlaceholder="Search permissions..."
                filterableColumns={[
                  {
                    id: 'resource',
                    title: 'Resource',
                    options: Array.from(groupedPermissions.keys()).map(
                      (resource) => ({
                        label: resource,
                        value: resource,
                      })
                    ),
                  },
                ]}
                loading={loading}
                pagination
                pageSize={25}
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
