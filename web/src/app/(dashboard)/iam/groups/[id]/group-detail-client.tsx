'use client';

import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, Loader2, Trash2 } from 'lucide-react';
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

export default function GroupDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const { toast } = useToast();

  const groupId = resolveDynamicId(params, pathname, 'groups');

  const { data: group, isLoading, error } = useApi(
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

  const g: any = (group as any)?.group ?? group ?? null;
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
    </div>
  );
}
