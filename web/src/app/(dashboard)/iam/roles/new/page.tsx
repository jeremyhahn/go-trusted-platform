'use client';

/**
 * Create Role page — minimal form that calls iam.createRole, then
 * routes back to /iam/roles.
 */

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useIAM, useToast, useMutation } from '@/hooks';
import { useAuth } from '@/contexts/AuthContext';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Button } from '@/components/ui/button';
import { Loader2 } from 'lucide-react';

export default function NewRolePage() {
  const router = useRouter();
  const { toast } = useToast();
  const iam = useIAM();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [permissions, setPermissions] = useState('');

  const createMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant available');
      const id = name.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
      const perms = permissions
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0);
      return iam.createRole({
        tenantId,
        id,
        name,
        description,
        permissions: perms,
      });
    },
    {
      onSuccess: () => {
        toast({ title: 'Role created', variant: 'success' });
        router.push('/iam/roles');
      },
      onError: (err) => {
        toast({
          title: 'Failed to create role',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      },
    },
  );

  if (authLoading) {
    return (
      <div className="container mx-auto py-6">
        <Loader2 className="h-6 w-6 animate-spin" />
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 max-w-2xl">
      <Card>
        <CardHeader>
          <CardTitle>Create Role</CardTitle>
          <CardDescription>
            Define a new role and the permissions it grants.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name *</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="admin"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Administrator role"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="permissions">Permissions (comma-separated)</Label>
            <Input
              id="permissions"
              value={permissions}
              onChange={(e) => setPermissions(e.target.value)}
              placeholder="read, write, *"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => router.push('/iam/roles')}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(undefined)}
              disabled={!name || createMutation.isLoading}
            >
              {createMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Create Role
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
