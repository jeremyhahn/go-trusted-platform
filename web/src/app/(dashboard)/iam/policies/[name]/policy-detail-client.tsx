'use client';

/**
 * Policy detail page — view and (eventually) edit a single IAM policy.
 *
 * The static export for /iam/policies/[name]/ pre-renders only the
 * `__placeholder__` segment, so we read the real policy name from the
 * URL pathname instead of `useParams()`.
 */

import React, { useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, Loader2, Pencil, Trash2 } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import type { UpdateIAMPolicyRequest } from 'trusted-platform-sdk';
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

// Policy record as the REST API sends it: camelCase or snake_case keys (#445).
interface PolicyWire {
  description?: string;
  priority?: number;
  spec_yaml?: string;
  specYaml?: string;
  spec?: string;
}

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

  const [editing, setEditing] = useState(false);
  const [draftDescription, setDraftDescription] = useState('');
  const [draftPriority, setDraftPriority] = useState('0');
  const [draftYaml, setDraftYaml] = useState('');

  const { data: policy, isLoading, error, refetch } = useApi(
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

  const updateMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      // The SDK request plus the spec key the REST API also reads.
      const request: UpdateIAMPolicyRequest & { spec_yaml: string } = {
        tenantId,
        policyName,
        description: draftDescription,
        priority: Number(draftPriority) || 0,
        specYaml: draftYaml,
        spec_yaml: draftYaml,
      };
      return iam.updatePolicy(request);
    },
    {
      onSuccess: () => {
        toast({ title: 'Policy updated', variant: 'success' });
        setEditing(false);
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to update policy',
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

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const rawPolicy = policy as unknown as (PolicyWire & { policy?: PolicyWire }) | null | undefined;
  const p: PolicyWire | null = rawPolicy?.policy ?? rawPolicy ?? null;
  const yaml: string = p?.spec_yaml ?? p?.specYaml ?? p?.spec ?? '';

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/policies')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Policies
        </Button>
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={editing}
            onClick={() => {
              setDraftDescription(p?.description ?? '');
              setDraftPriority(String(p?.priority ?? 0));
              setDraftYaml(yaml);
              setEditing(true);
            }}
          >
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
          {editing && (
            <div className="space-y-4 rounded-md border p-4">
              <div className="space-y-2">
                <Label htmlFor="policy-description">Description</Label>
                <Input
                  id="policy-description"
                  value={draftDescription}
                  onChange={(e) => setDraftDescription(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="policy-priority">Priority</Label>
                <Input
                  id="policy-priority"
                  type="number"
                  value={draftPriority}
                  onChange={(e) => setDraftPriority(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="policy-yaml">Spec (YAML)</Label>
                <Textarea
                  id="policy-yaml"
                  value={draftYaml}
                  onChange={(e) => setDraftYaml(e.target.value)}
                  rows={12}
                  className="font-mono text-xs"
                />
              </div>
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => setEditing(false)}>
                  Cancel
                </Button>
                <Button
                  disabled={updateMutation.isLoading}
                  onClick={() => {
                    if (window.confirm(`Save changes to policy "${policyName}"?`)) {
                      updateMutation.mutate(undefined);
                    }
                  }}
                >
                  {updateMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Save
                </Button>
              </div>
            </div>
          )}
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
