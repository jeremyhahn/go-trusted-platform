'use client';

/**
 * TenantDEKCard shows a tenant's data encryption key status and rotates the
 * key behind a confirm, through the SDK's TenantService. The status read is
 * withheld, with the server's reason, when its op is not offered, and Rotate
 * sits in the capability gate on its POST op (#2067).
 */

import { useCallback, useEffect, useState } from 'react';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useTenant } from '@/hooks';
import { useCapabilities } from '@/hooks/use-capabilities';

const STATUS_OP = 'GET /api/v1/tenants/{id}/dek';
const ROTATE_OP = 'POST /api/v1/tenants/{id}/dek/rotate';

interface DEKStatus {
  version?: number;
  algorithm?: string;
  status?: string;
  isDefault?: boolean;
  createdAt?: string;
}

interface Rotation {
  oldVersion?: number;
  newVersion?: number;
}

export function TenantDEKCard({ tenantId }: { tenantId: string }) {
  const tenant = useTenant();
  const statusCap = useCapabilities().capability(STATUS_OP);
  const [status, setStatus] = useState<DEKStatus | null>(null);
  const [rotation, setRotation] = useState<Rotation | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!statusCap.enabled) {
      return;
    }
    try {
      const res = await tenant.getDEKStatus(tenantId);
      if (res.success) {
        setStatus((res.data?.dekStatus ?? null) as DEKStatus | null);
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    }
  }, [tenant, tenantId, statusCap.enabled]);

  useEffect(() => {
    void load();
  }, [load]);

  const rotate = async () => {
    setConfirm(false);
    setBusy(true);
    setError(null);
    let succeeded = false;
    try {
      const res = await tenant.rotateDEK({ tenantId });
      if (res.success) {
        succeeded = true;
        setRotation((res.data ?? null) as Rotation | null);
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    } finally {
      setBusy(false);
    }
    if (succeeded) {
      await load();
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Data encryption key</CardTitle>
        <CardDescription>The tenant&apos;s data encryption key: its status and rotation.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {!statusCap.enabled ? (
          <p className="text-sm text-muted-foreground">{statusCap.reason}</p>
        ) : (
          <div data-testid="tenant-dek-status" className="flex flex-wrap gap-4 text-sm">
            {status && (
              <>
                <span>version {status.version}</span>
                {status.algorithm && <span>{status.algorithm}</span>}
                {status.status && <span>{status.status}</span>}
                {status.isDefault && <span>Default</span>}
                {status.createdAt && <span>Created {status.createdAt}</span>}
              </>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-end gap-4">
          <Gated op={ROTATE_OP}>
            <Button disabled={busy} onClick={() => setConfirm(true)}>
              Rotate DEK
            </Button>
          </Gated>
        </div>

        {rotation && (
          <p data-testid="tenant-dek-rotated" className="text-sm">
            Rotated from version {rotation.oldVersion} to version {rotation.newVersion}
          </p>
        )}

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}

        <Dialog open={confirm} onOpenChange={(open) => !open && setConfirm(false)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Rotate the tenant DEK?</DialogTitle>
              <DialogDescription>
                A new data encryption key version is created and used for new data; earlier versions stay readable.
              </DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirm(false)}>
                Cancel
              </Button>
              <Gated op={ROTATE_OP}>
                <Button disabled={busy} onClick={() => void rotate()}>
                  Rotate
                </Button>
              </Gated>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
