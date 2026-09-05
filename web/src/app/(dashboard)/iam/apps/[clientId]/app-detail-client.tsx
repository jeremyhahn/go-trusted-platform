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

export default function AppDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const { tenantId } = useAuth();
  const iam = useIAM();
  const { toast } = useToast();

  // Apps use `clientId` not `id` as the path param.
  const clientId = resolveDynamicId(params, pathname, 'apps', 'clientId');

  const { data: app, isLoading, error } = useApi(
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
  const a: any = (app as any)?.app ?? app ?? null;
  const redirectUris: string[] = a?.redirect_uris ?? a?.redirectUris ?? [];
  const grantTypes: string[] = a?.grant_types ?? a?.grantTypes ?? [];

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <Button variant="ghost" size="sm" onClick={() => router.push('/iam/apps')}>
          <ArrowLeft className="h-4 w-4 mr-2" /> Back to Applications
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
