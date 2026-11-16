'use client';

/**
 * Users List Page
 *
 * Displays all users in a searchable, filterable table with actions.
 * Uses the trusted-platform-sdk for API interactions.
 */

import React, { useState, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import type {
  LegacyUser,
  LegacyRole,
  CreateUserInput,
} from '@/types/iam';
import { UserTable } from '@/components/features/iam/user-table';
import { UserForm } from '@/components/features/iam/user-form';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Plus, Users, AlertCircle, Loader2 } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

/**
 * Users list page component
 */
export default function UsersPage() {
  const router = useRouter();
  const { toast } = useToast();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [isFormOpen, setIsFormOpen] = useState(false);
  const iam = useIAM();

  // Fetch users using SDK
  const {
    data: usersData,
    isLoading: usersLoading,
    error: usersError,
    refetch: refetchUsers,
  } = useApi(
    () => tenantId ? iam.listUsers({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [tenantId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading users',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch roles when form is open
  const {
    data: rolesData,
  } = useApi(
    () => (isFormOpen && tenantId) ? iam.listRoles({ tenantId }) : Promise.resolve({ success: true, data: null }),
    [isFormOpen, tenantId]
  );

  // Transform SDK users to LegacyUser for UI compatibility
  const users: LegacyUser[] = useMemo(() => {
    if (!usersData?.users) return [];
    return usersData.users.map((user) => ({
      id: user.id,
      email: user.email,
      name: user.name || user.email,
      avatarUrl: undefined,
      roles: (user.roles || []).map((r) => ({
        id: r,
        name: r,
        description: '',
        permissions: [],
        userCount: 0,
      })),
      permissions: [],
      status: 'active' as const,
      createdAt: user.createdAt || new Date().toISOString(),
      updatedAt: user.updatedAt || new Date().toISOString(),
      lastLoginAt: user.lastAuth,
    }));
  }, [usersData]);

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
      userCount: 0,
      createdAt: role.createdAt,
      updatedAt: role.updatedAt,
    }));
  }, [rolesData]);

  // Create user mutation
  const createUserMutation = useMutation(
    async (data: CreateUserInput) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.createUser({
        tenantId,
        email: data.email,
        name: data.name,
        roles: data.roleIds,
      });
    },
    {
      onSuccess: () => {
        toast({
          title: 'User created',
          description: 'The user has been created successfully',
          variant: 'success',
        });
        refetchUsers();
        setIsFormOpen(false);
      },
      onError: (error) => {
        toast({
          title: 'Error creating user',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Delete user mutation
  const deleteUserMutation = useMutation(
    async (userId: string) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.deleteUser(tenantId, userId);
    },
    {
      onSuccess: () => {
        toast({
          title: 'User deleted',
          description: 'The user has been deleted successfully',
          variant: 'success',
        });
        refetchUsers();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting user',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Toggle user status mutation
  const toggleUserStatusMutation = useMutation(
    async (user: LegacyUser) => {
      if (!tenantId) {
        throw new Error('No tenant ID available');
      }
      return iam.updateUser({
        tenantId,
        userId: user.id,
        name: user.name,
      });
    },
    {
      onSuccess: (_, user) => {
        toast({
          title: `User ${user.status === 'active' ? 'disabled' : 'enabled'}`,
          description: `The user has been ${user.status === 'active' ? 'disabled' : 'enabled'} successfully`,
          variant: 'success',
        });
        refetchUsers();
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

  const handleView = (user: LegacyUser) => {
    router.push(`/iam/users/${user.id}`);
  };

  const handleEdit = (user: LegacyUser) => {
    router.push(`/iam/users/${user.id}`);
  };

  const handleDisable = (user: LegacyUser) => {
    toggleUserStatusMutation.mutate(user);
  };

  const handleDelete = (user: LegacyUser) => {
    if (window.confirm(`Are you sure you want to delete ${user.name}?`)) {
      deleteUserMutation.mutate(user.id);
    }
  };

  const handleBulkDelete = useCallback(async (usersToDelete: LegacyUser[]) => {
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
        `Are you sure you want to delete ${usersToDelete.length} user(s)?`
      )
    ) {
      try {
        await Promise.all(
          usersToDelete.map((user) => iam.deleteUser(tenantId, user.id))
        );
        toast({
          title: 'Users deleted',
          description: `${usersToDelete.length} user(s) have been deleted successfully`,
          variant: 'success',
        });
        refetchUsers();
      } catch {
        toast({
          title: 'Error deleting users',
          description: 'Some users could not be deleted',
          variant: 'destructive',
        });
      }
    }
  }, [tenantId, iam, toast, refetchUsers]);

  const handleCreateUser = async (data: CreateUserInput) => {
    await createUserMutation.mutateAsync(data);
  };

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

  if (usersError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Users</AlertTitle>
          <AlertDescription>
            {usersError.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => refetchUsers()}
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
          <h1 className="text-3xl font-bold tracking-tight">Users</h1>
          <p className="text-muted-foreground">
            Manage user accounts and their role assignments
          </p>
        </div>
        <Button onClick={() => setIsFormOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add User
        </Button>
      </div>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter((u) => u.status === 'active').length || 0}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending Users</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {users?.filter((u) => u.status === 'pending').length || 0}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Users Table */}
      <Card>
        <CardContent className="pt-6">
          <UserTable
            users={users || []}
            loading={usersLoading}
            onView={handleView}
            onEdit={handleEdit}
            onDisable={handleDisable}
            onDelete={handleDelete}
            onBulkDelete={handleBulkDelete}
          />
        </CardContent>
      </Card>

      {/* User Form Dialog */}
      <UserForm
        open={isFormOpen}
        onOpenChange={setIsFormOpen}
        onSubmit={(data) => handleCreateUser(data as CreateUserInput)}
        roles={roles || []}
        loading={createUserMutation.isLoading}
      />
    </div>
  );
}
