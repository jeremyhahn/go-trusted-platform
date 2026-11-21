'use client';

import { useEffect, useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, Loader2, Trash2, UserMinus, UserPlus } from 'lucide-react';
import { resolveDynamicId } from '@/utils/dynamic-route';
import { useAuth } from '@/contexts/AuthContext';
import { useIAM, useApi, useMutation, useToast } from '@/hooks';
import { Button } from '@/components/ui/button';
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

// The SDK rejects with an error object carrying the server's message; it is
// not always an Error instance.
function failureMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err !== null && typeof err === 'object' && typeof (err as { message?: unknown }).message === 'string') {
    return (err as { message: string }).message;
  }
  return String(err);
}

// Group record as the REST API sends it: camelCase or snake_case keys (#445).
interface GroupWire {
  name?: string;
  description?: string;
  member_ids?: string[];
  members?: string[];
  memberIds?: string[];
  role_ids?: string[];
  roles?: string[];
  roleIds?: string[];
}

export default function GroupDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const { toast } = useToast();

  const groupId = resolveDynamicId(params, pathname, 'groups');

  const { data: group, isLoading, error, refetch } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.getGroup(tenantId, groupId);
    },
    [tenantId, groupId],
  );

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const rawGroup = group as unknown as (GroupWire & { group?: GroupWire }) | null | undefined;
  const g: GroupWire | null = rawGroup?.group ?? rawGroup ?? null;
  const members: string[] = g?.member_ids ?? g?.members ?? g?.memberIds ?? [];
  const roles: string[] = g?.role_ids ?? g?.roles ?? g?.roleIds ?? [];

  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');
  const [memberUserId, setMemberUserId] = useState('');
  const loadedName = g?.name ?? '';
  const loadedDescription = g?.description ?? '';

  // Seed the editor from the group the server holds, again after each re-read.
  useEffect(() => {
    setEditName(loadedName);
    setEditDescription(loadedDescription);
  }, [loadedName, loadedDescription]);

  const deleteMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.deleteGroup(tenantId, groupId);
    },
    {
      onSuccess: () => {
        toast({ title: 'Group deleted', variant: 'success' });
        router.push('/iam/groups');
      },
      onError: (err) => {
        toast({
          title: 'Failed to delete group',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const updateMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.updateGroup({ tenantId, groupId, name: editName.trim(), description: editDescription });
    },
    {
      onSuccess: () => {
        toast({ title: 'Group updated', variant: 'success' });
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to update group',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const addMemberMutation = useMutation(
    async (userId: string) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.addGroupMember({ tenantId, groupId, userId });
    },
    {
      onSuccess: () => {
        toast({ title: 'Member added', variant: 'success' });
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to add member',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const removeMemberMutation = useMutation(
    async (userId: string) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.removeGroupMember({ tenantId, groupId, userId });
    },
    {
      onSuccess: () => {
        toast({ title: 'Member removed', variant: 'success' });
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to remove member',
          description: failureMessage(err),
          variant: 'destructive',
        });
      },
    },
  );

  const trimmedUserId = memberUserId.trim();
  const memberBusy = addMemberMutation.isLoading || removeMemberMutation.isLoading;

  if (isLoading) {
    return (
      <div className="container mx-auto py-6 flex items-center gap-2">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading group…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/groups')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Groups
        </Button>
        <Card>
          <CardContent className="py-6">
            <p className="text-destructive">
              Error loading group: {error.message}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/groups')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Groups
        </Button>
        <Button
          variant="destructive"
          disabled={deleteMutation.isLoading}
          onClick={() => {
            if (window.confirm(`Delete group "${g?.name || groupId}"?`)) {
              deleteMutation.mutate(undefined);
            }
          }}
        >
          <Trash2 className="h-4 w-4 mr-2" /> Delete
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>{g?.name || groupId}</CardTitle>
          <CardDescription>{g?.description || 'No description'}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <Badge variant="outline">{members.length} members</Badge>
            <Badge variant="outline">{roles.length} roles</Badge>
          </div>
          {members.length > 0 && (
            <div>
              <h3 className="text-sm font-medium mb-2">Members</h3>
              <ul className="text-sm space-y-1">
                {members.map((m) => (
                  <li key={m} className="font-mono text-xs">
                    {m}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {roles.length > 0 && (
            <div>
              <h3 className="text-sm font-medium mb-2">Roles</h3>
              <ul className="text-sm space-y-1">
                {roles.map((r) => (
                  <li key={r} className="font-mono text-xs">
                    {r}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Edit group</CardTitle>
          <CardDescription>Change the group&apos;s name and description.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="group-name">Group name</Label>
            <Input id="group-name" value={editName} onChange={(e) => setEditName(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="group-description">Group description</Label>
            <Input
              id="group-description"
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
            />
          </div>
          <div className="flex justify-end">
            <Button
              onClick={() => updateMutation.mutate(undefined)}
              disabled={!editName.trim() || updateMutation.isLoading}
            >
              {updateMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Save group
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
          <CardDescription>
            The server&apos;s group record carries no member list, so members are managed by user ID.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="member-user-id">Member user ID</Label>
            <Input
              id="member-user-id"
              value={memberUserId}
              onChange={(e) => setMemberUserId(e.target.value)}
              placeholder="user ID"
            />
          </div>
          <div className="flex gap-2 justify-end">
            <Button
              onClick={() => addMemberMutation.mutate(trimmedUserId)}
              disabled={!trimmedUserId || memberBusy}
            >
              <UserPlus className="h-4 w-4 mr-2" /> Add member
            </Button>
            <Button
              variant="outline"
              onClick={() => removeMemberMutation.mutate(trimmedUserId)}
              disabled={!trimmedUserId || memberBusy}
            >
              <UserMinus className="h-4 w-4 mr-2" /> Remove member
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
