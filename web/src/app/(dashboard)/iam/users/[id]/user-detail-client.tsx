'use client';

/**
 * User Detail Page
 *
 * Displays detailed user information with role management and activity log.
 */

import React, { useState, useEffect } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { useAuth } from '@/contexts/AuthContext';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { LegacyUser, UpdateUserInput, LegacyRole, ActivityLogEntry } from '@/types/iam';
import { UserForm } from '@/components/features/iam/user-form';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Avatar } from '@/components/ui/avatar';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  ArrowLeft,
  Edit,
  Shield,
  Activity,
  Plus,
  X,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

/**
 * User detail page component
 */
export default function UserDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { toast } = useToast();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const userId = resolveDynamicId(params, pathname, 'users');

  const [isEditFormOpen, setIsEditFormOpen] = useState(false);

  // Fetch user using SDK
  const { data: user, isLoading: userLoading, error: userError, refetch: refetchUser } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.getUser(tenantId, userId);
    },
    [tenantId, userId]
  );

  // Fetch activities (placeholder - needs actual implementation in SDK if not available)
  const [activities, setActivities] = useState<ActivityLogEntry[]>([]);

  // Fetch roles using SDK only when edit form is opened
  const { data: rolesData } = useApi(
    () => {
      if (!isEditFormOpen || !tenantId) return Promise.reject(new Error('Not ready'));
      return iam.listRoles({ tenantId });
    },
    [isEditFormOpen, tenantId]
  );

  // The list reply is the proto ListIAMRolesResponse in protojson (#445).
  const allRoles = (rolesData?.roles || []).map((r) => ({
    id: r.id,
    name: r.name,
    description: r.description || '',
    permissions: (r.permissions || []).map((p: string) => ({
      id: p,
      name: p,
      resource: p.split(':')[0] || p,
      action: p.split(':')[1] || '*',
      description: `Permission: ${p}`
    })),
    userCount: 0,
    createdAt: r.createdAt,
    updatedAt: r.updatedAt
  }));

  // The server returns the user record directly as the response payload
  // (snake_case), but earlier client code expected a nested {user: …}
  // envelope with camelCase. Tolerate both shapes so the page works
  // regardless of which envelope the SDK returns.
  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const userRecord: any = (user as any)?.user ?? user ?? null;
  const legacyUser: LegacyUser | null = userRecord ? {
    id: userRecord.id,
    email: userRecord.email,
    name: userRecord.name,
    roles: ((userRecord.roles || userRecord.role_ids || []) as string[]).map((roleId: string) => {
      const roleData = allRoles.find((r: LegacyRole) => r.id === roleId);
      return roleData || {
        id: roleId,
        name: roleId,
        description: '',
        permissions: [],
        userCount: 0,
        createdAt: '',
        updatedAt: ''
      };
    }),
    permissions: [],
    status: 'active',
    createdAt: userRecord.createdAt ?? userRecord.created_at,
    updatedAt: userRecord.updatedAt ?? userRecord.updated_at,
    lastLoginAt: userRecord.lastAuth ?? userRecord.last_auth,
    avatarUrl: undefined
  } : null;

  // Update user mutation using SDK
  const updateUserMutation = useMutation(
    (data: UpdateUserInput) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.updateUser({
        tenantId,
        userId,
        email: data.email,
        name: data.name,
        roles: data.roleIds
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'User updated',
          description: 'The user has been updated successfully',
          variant: 'success',
        });
        refetchUser();
        setIsEditFormOpen(false);
      },
      onError: (error) => {
        toast({
          title: 'Error updating user',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Add role mutation using SDK
  const addRoleMutation = useMutation(
    (roleId: string) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.assignRole({ tenantId, userId, roleId });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Role assigned',
          description: 'The role has been assigned successfully',
          variant: 'success',
        });
        refetchUser();
      },
      onError: (error) => {
        toast({
          title: 'Error assigning role',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Remove role mutation using SDK
  const removeRoleMutation = useMutation(
    (roleId: string) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.revokeRole({ tenantId, userId, roleId });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Role removed',
          description: 'The role has been removed successfully',
          variant: 'success',
        });
        refetchUser();
      },
      onError: (error) => {
        toast({
          title: 'Error removing role',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleUpdateUser = async (data: UpdateUserInput) => {
    await updateUserMutation.mutateAsync(data);
  };

  const handleRemoveRole = (roleId: string) => {
    if (window.confirm('Are you sure you want to remove this role?')) {
      removeRoleMutation.mutate(roleId);
    }
  };

  if (userError) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6">
            <p className="text-destructive">
              Error loading user: {userError instanceof Error ? userError.message : 'Failed to load user'}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  if (userLoading || !legacyUser) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6">
            <p className="text-muted-foreground">Loading user details...</p>
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
            onClick={() => router.push('/iam/users')}
          >
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="space-y-1">
            <h1 className="text-3xl font-bold tracking-tight">User Details</h1>
            <p className="text-muted-foreground">
              View and manage user information
            </p>
          </div>
        </div>
        <Button onClick={() => setIsEditFormOpen(true)}>
          <Edit className="mr-2 h-4 w-4" />
          Edit User
        </Button>
      </div>

      {/* User Info Card */}
      <Card>
        <CardHeader>
          <CardTitle>User Information</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-start gap-6">
            <Avatar className="h-20 w-20">
              {legacyUser.avatarUrl ? (
                <img src={legacyUser.avatarUrl} alt={legacyUser.name} />
              ) : (
                <div className="flex h-full w-full items-center justify-center bg-primary text-primary-foreground text-2xl font-medium">
                  {legacyUser.name.charAt(0).toUpperCase()}
                </div>
              )}
            </Avatar>
            <div className="flex-1 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Name
                  </p>
                  <p className="text-lg font-medium">{legacyUser.name}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Email
                  </p>
                  <p className="text-lg font-medium">{legacyUser.email}</p>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Status
                  </p>
                  <Badge
                    variant={
                      legacyUser.status === 'active'
                        ? 'default'
                        : legacyUser.status === 'disabled'
                        ? 'destructive'
                        : 'secondary'
                    }
                  >
                    {legacyUser.status.charAt(0).toUpperCase() + legacyUser.status.slice(1)}
                  </Badge>
                </div>
                <div>
                  <p className="text-sm font-medium text-muted-foreground">
                    Last Login
                  </p>
                  <p className="text-sm">
                    {legacyUser.lastLoginAt
                      ? formatDistanceToNow(new Date(legacyUser.lastLoginAt), {
                          addSuffix: true,
                        })
                      : 'Never'}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs defaultValue="roles" className="space-y-4">
        <TabsList>
          <TabsTrigger value="roles">
            <Shield className="mr-2 h-4 w-4" />
            Roles & Permissions
          </TabsTrigger>
          <TabsTrigger value="activity">
            <Activity className="mr-2 h-4 w-4" />
            Activity Log
          </TabsTrigger>
        </TabsList>

        {/* Roles Tab */}
        <TabsContent value="roles" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Assigned Roles</CardTitle>
                  <CardDescription>
                    Roles grant users specific permissions
                  </CardDescription>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {legacyUser.roles.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No roles assigned
                </p>
              ) : (
                <div className="space-y-2">
                  {legacyUser.roles.map((role) => (
                    <div
                      key={role.id}
                      className="flex items-center justify-between p-3 border rounded-md"
                    >
                      <div className="space-y-1">
                        <p className="font-medium">{role.name}</p>
                        <p className="text-sm text-muted-foreground">
                          {role.description}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {role.permissions.length} permission
                          {role.permissions.length !== 1 ? 's' : ''}
                        </p>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleRemoveRole(role.id)}
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Direct Permissions</CardTitle>
              <CardDescription>
                Permissions assigned directly to the user
              </CardDescription>
            </CardHeader>
            <CardContent>
              {legacyUser.permissions.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No direct permissions
                </p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {legacyUser.permissions.map((permission) => (
                    <Badge key={permission.id} variant="outline">
                      {permission.resource}:{permission.action}
                    </Badge>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Activity Tab */}
        <TabsContent value="activity">
          <Card>
            <CardHeader>
              <CardTitle>Activity Log</CardTitle>
              <CardDescription>
                Recent actions performed by this user
              </CardDescription>
            </CardHeader>
            <CardContent>
              {!activities || activities.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No activity logged
                </p>
              ) : (
                <div className="space-y-3">
                  {activities.map((activity) => (
                    <div
                      key={activity.id}
                      className="flex items-start gap-3 p-3 border rounded-md"
                    >
                      <Activity className="h-4 w-4 mt-1 text-muted-foreground" />
                      <div className="flex-1 space-y-1">
                        <div className="flex items-start justify-between">
                          <p className="text-sm font-medium">
                            {activity.action}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {formatDistanceToNow(new Date(activity.timestamp), {
                              addSuffix: true,
                            })}
                          </p>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {activity.resource}
                        </p>
                        {activity.ipAddress && (
                          <p className="text-xs text-muted-foreground">
                            IP: {activity.ipAddress}
                          </p>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Edit User Form Dialog */}
      <UserForm
        open={isEditFormOpen}
        onOpenChange={setIsEditFormOpen}
        onSubmit={handleUpdateUser}
        user={legacyUser}
        roles={allRoles}
        loading={updateUserMutation.isLoading}
      />
    </div>
  );
}
