'use client';

/**
 * Role Detail Page
 *
 * Displays detailed role information with permission management and assigned users.
 */

import React, { useState, useEffect } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { useAuth } from '@/contexts/AuthContext';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { LegacyRole, UpdateRoleInput, LegacyUser, Permission } from '@/types/iam';
import { PermissionTree } from '@/components/features/iam/permission-tree';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ArrowLeft, Edit, Save, X, Shield, Users } from 'lucide-react';
import { Avatar } from '@/components/ui/avatar';

/**
 * Role detail page component
 */
export default function RoleDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const roleId = resolveDynamicId(params, pathname, 'roles');

  const [isEditing, setIsEditing] = useState(false);
  const [editedName, setEditedName] = useState('');
  const [editedDescription, setEditedDescription] = useState('');
  const [selectedPermissionIds, setSelectedPermissionIds] = useState<string[]>(
    []
  );

  // Fetch role using SDK
  const { data: role, isLoading: roleLoading, error: roleError, refetch: refetchRole } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.getRole(tenantId, roleId);
    },
    [tenantId, roleId]
  );

  // Fetch users (placeholder - needs actual implementation in SDK if not available)
  const [users, setUsers] = useState<LegacyUser[]>([]);

  // Fetch permissions (placeholder - needs actual implementation in SDK if not available)
  const [allPermissions, setAllPermissions] = useState<Permission[]>([]);

  // Tolerate both the legacy {role: …} envelope and the current direct
  // payload shape; also accept snake_case timestamps from the server.
  const roleRecord: any = (role as any)?.role ?? role ?? null;
  const legacyRole: LegacyRole | null = roleRecord ? {
    id: roleRecord.id,
    name: roleRecord.name,
    description: roleRecord.description || '',
    permissions: ((roleRecord.permissions || []) as string[]).map((p: string) => ({
      id: p,
      name: p,
      resource: p.split(':')[0] || p,
      action: p.split(':')[1] || '*',
      description: `Permission: ${p}`
    })),
    userCount: users.length,
    createdAt: roleRecord.createdAt ?? roleRecord.created_at,
    updatedAt: roleRecord.updatedAt ?? roleRecord.updated_at
  } : null;

  // Update state when role data changes
  useEffect(() => {
    if (legacyRole) {
      setEditedName(legacyRole.name);
      setEditedDescription(legacyRole.description);
      setSelectedPermissionIds(legacyRole.permissions.map((p) => p.id));
    }
  }, [legacyRole]);

  // Update role mutation using SDK
  const updateRoleMutation = useMutation(
    (data: UpdateRoleInput) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.updateRole({
        tenantId,
        roleId,
        name: data.name,
        description: data.description,
        permissions: data.permissionIds
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Role updated',
          description: 'The role has been updated successfully',
          variant: 'success',
        });
        refetchRole();
        setIsEditing(false);
      },
      onError: (error) => {
        toast({
          title: 'Error updating role',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleSave = () => {
    if (!editedName.trim()) {
      toast({
        title: 'Validation error',
        description: 'Role name is required',
        variant: 'destructive',
      });
      return;
    }

    updateRoleMutation.mutate({
      name: editedName,
      description: editedDescription,
      permissionIds: selectedPermissionIds,
    });
  };

  const handleCancel = () => {
    if (legacyRole) {
      setEditedName(legacyRole.name);
      setEditedDescription(legacyRole.description);
      setSelectedPermissionIds(legacyRole.permissions.map((p) => p.id));
    }
    setIsEditing(false);
  };

  if (roleError) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6">
            <p className="text-destructive">
              Error loading role: {roleError instanceof Error ? roleError.message : 'Failed to load role'}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (roleLoading || !legacyRole) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6">
            <p className="text-muted-foreground">Loading role details...</p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => router.push('/iam/roles')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="space-y-1">
            <h1 className="text-3xl font-bold tracking-tight">Role Details</h1>
            <p className="text-muted-foreground">
              View and manage role permissions
            </p>
          </div>
        </div>
        {isEditing ? (
          <div className="flex gap-2">
            <Button variant="outline" onClick={handleCancel}>
              <X className="mr-2 h-4 w-4" />
              Cancel
            </Button>
            <Button
              onClick={handleSave}
              disabled={updateRoleMutation.isLoading}
            >
              <Save className="mr-2 h-4 w-4" />
              Save Changes
            </Button>
          </div>
        ) : (
          <Button onClick={() => setIsEditing(true)}>
            <Edit className="mr-2 h-4 w-4" />
            Edit Role
          </Button>
        )}
      </div>

      {/* Role Info Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Role Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          {isEditing ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="name">
                  Role Name <span className="text-destructive">*</span>
                </Label>
                <Input
                  id="name"
                  value={editedName}
                  onChange={(e) => setEditedName(e.target.value)}
                  placeholder="Administrator"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Input
                  id="description"
                  value={editedDescription}
                  onChange={(e) => setEditedDescription(e.target.value)}
                  placeholder="Full system access"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-4">
              <div>
                <p className="text-sm font-medium text-muted-foreground">
                  Role Name
                </p>
                <p className="text-lg font-medium">{legacyRole.name}</p>
              </div>
              <div>
                <p className="text-sm font-medium text-muted-foreground">
                  Description
                </p>
                <p className="text-sm">{legacyRole.description}</p>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Users with this role
                  </p>
                  <p className="text-2xl font-bold">{legacyRole.userCount}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Permissions
                  </p>
                  <p className="text-2xl font-bold">
                    {legacyRole.permissions.length}
                  </p>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs defaultValue="permissions" className="space-y-4">
        <TabsList>
          <TabsTrigger value="permissions">
            <Shield className="mr-2 h-4 w-4" />
            Permissions
          </TabsTrigger>
          <TabsTrigger value="users">
            <Users className="mr-2 h-4 w-4" />
            Users ({legacyRole.userCount})
          </TabsTrigger>
        </TabsList>

        {/* Permissions Tab */}
        <TabsContent value="permissions">
          <Card>
            <CardHeader>
              <CardTitle>Permissions</CardTitle>
              <CardDescription>
                {isEditing
                  ? 'Select permissions to grant to this role'
                  : 'Permissions granted by this role'}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isEditing ? (
                <PermissionTree
                  permissions={allPermissions || []}
                  selectedPermissionIds={selectedPermissionIds}
                  onChange={setSelectedPermissionIds}
                />
              ) : (
                <div>
                  {legacyRole.permissions.length === 0 ? (
                    <p className="text-sm text-muted-foreground text-center py-4">
                      No permissions assigned
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {Object.entries(
                        legacyRole.permissions.reduce((acc, permission) => {
                          if (!acc[permission.resource]) {
                            acc[permission.resource] = [];
                          }
                          acc[permission.resource].push(permission);
                          return acc;
                        }, {} as Record<string, Permission[]>)
                      ).map(([resource, permissions]) => (
                        <div key={resource} className="space-y-2">
                          <p className="font-medium text-sm">{resource}</p>
                          <div className="flex flex-wrap gap-2 ml-4">
                            {permissions.map((permission) => (
                              <Badge key={permission.id} variant="outline">
                                {permission.action}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Users Tab */}
        <TabsContent value="users">
          <Card>
            <CardHeader>
              <CardTitle>Users with this role</CardTitle>
              <CardDescription>
                Users who have been assigned this role
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!users || users.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No users assigned
                </p>
              ) : (
                <div className="space-y-2">
                  {users.map((user) => (
                    <div
                      key={user.id}
                      className="flex items-center gap-3 p-3 border rounded-md hover:bg-accent cursor-pointer"
                      onClick={() => router.push(`/iam/users/${user.id}`)}
                    >
                      <Avatar className="h-8 w-8">
                        {user.avatarUrl ? (
                          <img src={user.avatarUrl} alt={user.name} />
                        ) : (
                          <div className="flex h-full w-full items-center justify-center bg-primary text-primary-foreground text-sm font-medium">
                            {user.name.charAt(0).toUpperCase()}
                          </div>
                        )}
                      </Avatar>
                      <div className="flex-1">
                        <p className="font-medium">{user.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {user.email}
                        </p>
                      </div>
                      <Badge
                        variant={
                          user.status === 'active'
                            ? 'default'
                            : user.status === 'disabled'
                            ? 'destructive'
                            : 'secondary'
                        }
                      >
                        {user.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
