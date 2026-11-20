'use client';

import { useParams, usePathname, useRouter } from 'next/navigation';
import { useState } from 'react';
import { ArrowLeft, Loader2, Trash2, UserMinus, UserPlus } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
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
import { EmbeddedIamGate } from '../../embedded-iam-gate';

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
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      },
    },
  );

  const [editName, setEditName] = useState<string | null>(null);
  const [editDescription, setEditDescription] = useState<string | null>(null);
  const [newMember, setNewMember] = useState('');
  const [removeMember, setRemoveMember] = useState('');

  const failToast = (title: string) => (err: unknown) => {
    toast({
      title,
      description: err instanceof Error ? err.message : 'Unknown error',
      variant: 'destructive',
    });
  };

  const updateMutation = useMutation(
    async (vars: { name: string; description: string }) => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.updateGroup({ tenantId, groupId, ...vars });
    },
    {
      onSuccess: () => {
        toast({ title: 'Group updated', variant: 'success' });
        refetch();
      },
      onError: failToast('Failed to update group'),
    },
  );

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

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const rawGroup = group as unknown as (GroupWire & { group?: GroupWire }) | null | undefined;
  const g: GroupWire | null = rawGroup?.group ?? rawGroup ?? null;
  const members: string[] = g?.member_ids ?? g?.members ?? g?.memberIds ?? [];
  const roles: string[] = g?.role_ids ?? g?.roles ?? g?.roleIds ?? [];

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
            {members.length > 0 && <Badge variant="outline">{members.length} members</Badge>}
            <Badge variant="outline">{roles.length} roles</Badge>
          </div>
          {members.length > 0 && (
            <div>
              <h3 className="text-sm font-medium mb-2">Members</h3>
              <ul className="text-sm space-y-1">
                {members.map((m) => (
                  <li key={m} className="font-mono text-xs flex items-center gap-2">
                    <span>{m}</span>
                    <EmbeddedIamGate
                      method="Group.RemoveMember"
                      showReason={false}
                      size="sm"
                      variant="ghost"
                      aria-label={`Remove member ${m}`}
                    >
                      <UserMinus className="h-4 w-4" />
                    </EmbeddedIamGate>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <form
            className="flex items-end gap-2"
            // The embedded IAM backend has no Group.AddMember handler (#2024 Codex).
            onSubmit={(e) => e.preventDefault()}
          >
            <div className="space-y-2 flex-1">
              <Label htmlFor="group-new-member">User ID</Label>
              <Input
                id="group-new-member"
                value={newMember}
                onChange={(e) => setNewMember(e.target.value)}
              />
            </div>
            <EmbeddedIamGate method="Group.AddMember">
              <UserPlus className="h-4 w-4 mr-2" /> Add member
            </EmbeddedIamGate>
          </form>
          {/* GET /groups/{id} carries no members list (groupToResponse), so removal goes by user ID. */}
          <form
            className="flex items-end gap-2"
            // The embedded IAM backend has no Group.RemoveMember handler (#2024 Codex).
            onSubmit={(e) => e.preventDefault()}
          >
            <div className="space-y-2 flex-1">
              <Label htmlFor="group-remove-member">User ID to remove</Label>
              <Input
                id="group-remove-member"
                value={removeMember}
                onChange={(e) => setRemoveMember(e.target.value)}
              />
            </div>
            <EmbeddedIamGate method="Group.RemoveMember" variant="outline">
              <UserMinus className="h-4 w-4 mr-2" /> Remove by user ID
            </EmbeddedIamGate>
          </form>
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
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              updateMutation.mutate({
                name: editName ?? g?.name ?? '',
                description: editDescription ?? g?.description ?? '',
              });
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="group-edit-name">Name</Label>
              <Input
                id="group-edit-name"
                value={editName ?? g?.name ?? ''}
                onChange={(e) => setEditName(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="group-edit-description">Description</Label>
              <Input
                id="group-edit-description"
                value={editDescription ?? g?.description ?? ''}
                onChange={(e) => setEditDescription(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={updateMutation.isLoading}>
              Save group
            </Button>
          </form>
        </CardContent>
      </Card>

    </div>
  );
}
