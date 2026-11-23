'use client';

/**
 * TenantBarrierCard shows a tenant's barrier status and offers Initialize,
 * Unseal and Seal, each in the capability gate on its POST op. The status read
 * is withheld, with the server's reason, when its op is not offered (#2067).
 */

import { useCallback, useEffect, useState } from 'react';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useTenantBarrier, type TenantBarrierStatus } from '@/hooks/use-tenant-barrier';

interface ActionResult {
  success: boolean;
  error?: { message?: string };
}

export function TenantBarrierCard({ tenantId }: { tenantId: string }) {
  const barrier = useTenantBarrier();
  const statusCap = useCapabilities().capability('GET /api/v1/tenants/{id}/barrier');
  const [status, setStatus] = useState<TenantBarrierStatus | null>(null);
  const [threshold, setThreshold] = useState('3');
  const [shares, setShares] = useState('5');
  const [unsealKey, setUnsealKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!statusCap.enabled) {
      return;
    }
    try {
      const res = await barrier.getStatus(tenantId);
      if (res.success) {
        setStatus(res.data?.barrierStatus ?? null);
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    }
  }, [barrier, tenantId, statusCap.enabled]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (action: () => Promise<ActionResult>) => {
    setBusy(true);
    setError(null);
    try {
      const res = await action();
      if (!res.success) {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    } finally {
      setBusy(false);
    }
    await load();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Barrier</CardTitle>
        <CardDescription>The tenant&apos;s key barrier: its status, initialization, unseal and seal.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!statusCap.enabled ? (
          <p className="text-sm text-muted-foreground">{statusCap.reason}</p>
        ) : (
          <div data-testid="tenant-barrier-status" className="flex flex-wrap gap-4 text-sm">
            {status && (
              <>
                <span>{status.sealed ? 'Sealed' : 'Unsealed'}</span>
                <span>{status.initialized ? 'Initialized' : 'Not initialized'}</span>
                {status.strategy && <span>{status.strategy}</span>}
                {status.hardwareBacked && <span>Hardware-backed</span>}
              </>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="tenant-barrier-threshold">Threshold</Label>
            <Input
              id="tenant-barrier-threshold"
              type="number"
              min={1}
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="tenant-barrier-shares">Shares</Label>
            <Input
              id="tenant-barrier-shares"
              type="number"
              min={1}
              value={shares}
              onChange={(e) => setShares(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/tenants/{id}/barrier/init">
            <Button
              disabled={busy}
              onClick={() => run(() => barrier.init(tenantId, Number(threshold), Number(shares)))}
            >
              Initialize
            </Button>
          </Gated>
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="tenant-barrier-unseal-key">Unseal key</Label>
            <Input
              id="tenant-barrier-unseal-key"
              value={unsealKey}
              onChange={(e) => setUnsealKey(e.target.value)}
            />
          </div>
          <Gated op="POST /api/v1/tenants/{id}/barrier/unseal">
            <Button disabled={busy} onClick={() => run(() => barrier.unseal(tenantId, unsealKey))}>
              Unseal
            </Button>
          </Gated>
          <Gated op="POST /api/v1/tenants/{id}/barrier/seal">
            <Button variant="outline" disabled={busy} onClick={() => run(() => barrier.seal(tenantId))}>
              Seal
            </Button>
          </Gated>
        </div>

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
