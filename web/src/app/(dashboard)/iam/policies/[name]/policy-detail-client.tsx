'use client';

/**
 * Policy detail page — view and (eventually) edit a single IAM policy.
 *
 * The static export for /iam/policies/[name]/ pre-renders only the
 * `__placeholder__` segment, so we read the real policy name from the
 * URL pathname instead of `useParams()`.
 */

import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, Loader2, Pencil, Trash2 } from 'lucide-react';
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

export default function PolicyDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const { toast } = useToast();

  const policyName = decodeURIComponent(
    resolveDynamicId(params, pathname, 'policies', 'name'),
  );

  const { data: policy, isLoading, error } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.getPolicy(tenantId, policyName);
    },
    [tenantId, policyName],
  );

  const deleteMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.deletePolicy(tenantId, policyName);
    },
    {
      onSuccess: () => {
        toast({ title: 'Policy deleted', variant: 'success' });
        router.push('/iam/policies');
      },
      onError: (err) => {
        toast({
          title: 'Failed to delete policy',
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
        <span>Loading policy…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/policies')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Policies
        </Button>
        <Card>
          <CardContent className="py-6">
            <p className="text-destructive">
              Error loading policy: {error.message}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  const p: any = (policy as any)?.policy ?? policy ?? null;
  const yaml: string = p?.spec_yaml ?? p?.specYaml ?? p?.spec ?? '';

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/policies')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Policies
        </Button>
        <div className="flex gap-2">
          <Button variant="outline" disabled>
            <Pencil className="h-4 w-4 mr-2" /> Edit
          </Button>
          <Button
            variant="destructive"
            disabled={deleteMutation.isLoading}
            onClick={() => {
              if (window.confirm(`Delete policy "${policyName}"?`)) {
                deleteMutation.mutate(undefined);
              }
            }}
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {policyName}
            <Badge variant="outline">priority {p?.priority ?? 0}</Badge>
          </CardTitle>
          <CardDescription>{p?.description || 'No description'}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="text-sm font-medium mb-2">Spec (YAML)</h3>
            <pre className="rounded-md border bg-muted p-4 text-xs overflow-auto max-h-[500px]">
              {yaml || '(no spec returned)'}
            </pre>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
