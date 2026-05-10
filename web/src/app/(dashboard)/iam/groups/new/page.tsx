'use client';

/**
 * Create Group page — minimal form that calls iam.createGroup, then
 * routes back to /iam/groups. The list page links here from its
 * "Add Group" button.
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

export default function NewGroupPage() {
  const router = useRouter();
  const { toast } = useToast();
  const iam = useIAM();
  const { tenantId, isLoading: authLoading } = useAuth();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');

  const createMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant available');
      const id = name.toLowerCase().replace(/[^a-z0-9-]+/g, '-');
      return iam.createGroup({ tenantId, id, name, description });
    },
    {
      onSuccess: () => {
        toast({ title: 'Group created', variant: 'success' });
        router.push('/iam/groups');
      },
      onError: (err) => {
        toast({
          title: 'Failed to create group',
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
          <CardTitle>Create Group</CardTitle>
          <CardDescription>
            Add a new group to organize users and assign roles.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="name">Name *</Label>
            <Input
              id="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="engineering"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description</Label>
            <Input
              id="description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Engineering team"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => router.push('/iam/groups')}>
              Cancel
            </Button>
            <Button
              onClick={() => createMutation.mutate(undefined)}
              disabled={!name || createMutation.isLoading}
            >
              {createMutation.isLoading && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Create Group
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
