'use client';

/**
 * TenantDEKStatusCard — a tenant's data encryption key status from the
 * control plane's GetTenantDEKStatus, and a Sync tenants action (#2067).
 *
 * Sync is a system-tenant operation; the control plane answers a partial
 * sync with `status.success: false` (HTTP 200), which is reported as
 * incomplete, and a refusal verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useToast } from '@/hooks/use-toast';
import { useTenantChecks, type TenantDEKStatus } from '@/hooks/use-tenant-checks';

export function TenantDEKStatusCard({ tenantId }: { tenantId: string }): JSX.Element {
  const checks = useTenantChecks();
  const { toast } = useToast();
  const [dek, setDEK] = useState<TenantDEKStatus | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    setRefusal(null);
    try {
      const res = await checks.getDEKStatus(tenantId);
      if (res.success && res.data) {
        setDEK(res.data.dekStatus ?? null);
      } else {
        setDEK(null);
        setRefusal(res.error?.message || 'The control plane did not answer the DEK status');
      }
    } catch (err) {
      setDEK(null);
      setRefusal(err instanceof Error ? err.message : String(err));
    }
  }, [checks, tenantId]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const handleSync = async () => {
    setBusy(true);
    try {
      const res = await checks.sync();
      if (res.success && res.data?.status?.success !== false) {
        toast({ title: 'Tenants synced', description: res.data?.status?.message ?? '', variant: 'success' });
      } else if (res.success) {
        toast({ title: 'Sync incomplete', description: res.data?.status?.message ?? '', variant: 'destructive' });
      } else {
        toast({
          title: 'Sync failed',
          description: res.error?.message || 'The control plane did not sync the tenants',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Sync failed', description: err instanceof Error ? err.message : String(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="tenant-dek-status-card">
      <CardHeader className="flex flex-row items-start justify-between space-y-0">
        <div>
          <CardTitle>Data encryption key</CardTitle>
          <CardDescription>The DEK status of tenant {tenantId}.</CardDescription>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void reload()}>
            Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={handleSync} disabled={busy}>
            Sync tenants
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {dek && (
          <dl data-testid="tenant-dek-status" className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Version</dt>
            <dd>{dek.version ?? '-'}</dd>
            <dt className="text-muted-foreground">Algorithm</dt>
            <dd>{dek.algorithm ?? '-'}</dd>
            <dt className="text-muted-foreground">Status</dt>
            <dd>{dek.status ?? '-'}</dd>
            <dt className="text-muted-foreground">Uses</dt>
            <dd>
              {dek.usageCount ?? 0} / {dek.maxUsageCount ?? '-'}
            </dd>
            <dt className="text-muted-foreground">Usage</dt>
            <dd>{Math.round(dek.usagePercent ?? 0)}%</dd>
            <dt className="text-muted-foreground">Rotation</dt>
            <dd>
              <Badge data-testid="tenant-dek-rotation" variant={dek.needsRotation ? 'destructive' : 'secondary'}>
                {dek.needsRotation ? 'Rotation due' : 'Current'}
              </Badge>
            </dd>
          </dl>
        )}
        {refusal !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {refusal}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
