'use client';

import React, { useState } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { ArrowLeft, Loader2, Pencil, Trash2 } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { splitList } from '@/hooks';
import type { UpdateIAMAppRequest } from 'trusted-platform-sdk';
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

// Application record as the REST API sends it: camelCase or snake_case keys (#445).
interface AppWire {
  name?: string;
  redirect_uris?: string[];
  redirectUris?: string[];
  grant_types?: string[];
  grantTypes?: string[];
  created_at?: string;
}

export default function AppDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const { toast } = useToast();

  // Apps use `clientId` not `id` as the path param.
  const clientId = resolveDynamicId(params, pathname, 'apps', 'clientId');

  const [editing, setEditing] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [draftRedirectUris, setDraftRedirectUris] = useState('');
  const [draftGrantTypes, setDraftGrantTypes] = useState('');

  const { data: app, isLoading, error, refetch } = useApi(
    () => {
      if (!tenantId) return Promise.reject(new Error('No tenant ID'));
      return iam.getApp(tenantId, clientId);
    },
    [tenantId, clientId],
  );

  const deleteMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      return iam.deleteApp(tenantId, clientId);
    },
    {
      onSuccess: () => {
        toast({ title: 'Application deleted', variant: 'success' });
        router.push('/iam/apps');
      },
      onError: (err) => {
        toast({
          title: 'Failed to delete application',
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
      },
    },
  );

  const updateMutation = useMutation(
    async () => {
      if (!tenantId) throw new Error('No tenant ID');
      const redirectUris = splitList(draftRedirectUris);
      const grantTypes = splitList(draftGrantTypes);
      // The SDK request plus the snake_case keys the REST API also reads.
      const request: UpdateIAMAppRequest & { redirect_uris: string[]; grant_types: string[] } = {
        tenantId,
        clientId,
        name: draftName,
        redirectUris,
        grantTypes,
        redirect_uris: redirectUris,
        grant_types: grantTypes,
      };
      return iam.updateApp(request);
    },
    {
      onSuccess: () => {
        toast({ title: 'Application updated', variant: 'success' });
        setEditing(false);
        void refetch();
      },
      onError: (err) => {
        toast({
          title: 'Failed to update application',
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
        <span>Loading application…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-6 space-y-4">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/apps')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Applications
        </Button>
        <Card>
          <CardContent className="py-6">
            <p className="text-destructive">
              Error loading application: {error.message}
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const rawApp = app as unknown as (AppWire & { app?: AppWire }) | null | undefined;
  const a: AppWire | null = rawApp?.app ?? rawApp ?? null;
  const redirectUris: string[] = a?.redirect_uris ?? a?.redirectUris ?? [];
  const grantTypes: string[] = a?.grant_types ?? a?.grantTypes ?? [];

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/apps')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Applications
        </Button>
        <div className="flex gap-2">
          <Button
            variant="outline"
            disabled={editing}
            onClick={() => {
              setDraftName(a?.name ?? '');
              setDraftRedirectUris(redirectUris.join(', '));
              setDraftGrantTypes(grantTypes.join(', '));
              setEditing(true);
            }}
          >
            <Pencil className="h-4 w-4 mr-2" /> Edit
          </Button>
          <Button
            variant="destructive"
            disabled={deleteMutation.isLoading}
            onClick={() => {
              if (window.confirm(`Delete application "${a?.name || clientId}"?`)) {
                deleteMutation.mutate(undefined);
              }
            }}
          >
            <Trash2 className="h-4 w-4 mr-2" /> Delete
          </Button>
        </div>
      </div>

      {editing && (
        <Card>
          <CardHeader>
            <CardTitle>Edit Application</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="app-name">Name</Label>
              <Input id="app-name" value={draftName} onChange={(e) => setDraftName(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="app-redirect-uris">Redirect URIs (comma-separated)</Label>
              <Input
                id="app-redirect-uris"
                value={draftRedirectUris}
                onChange={(e) => setDraftRedirectUris(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="app-grant-types">Grant Types (comma-separated)</Label>
              <Input
                id="app-grant-types"
                value={draftGrantTypes}
                onChange={(e) => setDraftGrantTypes(e.target.value)}
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setEditing(false)}>
                Cancel
              </Button>
              <Button
                disabled={!draftName || updateMutation.isLoading}
                onClick={() => {
                  if (window.confirm(`Save changes to application "${a?.name || clientId}"?`)) {
                    updateMutation.mutate(undefined);
                  }
                }}
              >
                {updateMutation.isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Save
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{a?.name || clientId}</CardTitle>
          <CardDescription className="font-mono text-xs">{clientId}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="text-sm font-medium mb-2">Grant Types</h3>
            <div className="flex flex-wrap gap-1">
              {grantTypes.length === 0 ? (
                <span className="text-sm text-muted-foreground">— none —</span>
              ) : (
                grantTypes.map((g) => (
                  <Badge key={g} variant="outline">
                    {g}
                  </Badge>
                ))
              )}
            </div>
          </div>
          <div>
            <h3 className="text-sm font-medium mb-2">Redirect URIs</h3>
            {redirectUris.length === 0 ? (
              <span className="text-sm text-muted-foreground">— none —</span>
            ) : (
              <ul className="text-sm space-y-1">
                {redirectUris.map((u) => (
                  <li key={u} className="font-mono text-xs">
                    {u}
                  </li>
                ))}
              </ul>
            )}
          </div>
          {a?.created_at && (
            <div className="text-xs text-muted-foreground">
              Created {new Date(a.created_at).toLocaleString()}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
