'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams, usePathname, useSearchParams } from 'next/navigation';
import { RefreshCw } from 'lucide-react';
import { isServiceNotConfigured, type Snapshot } from 'trusted-platform-sdk';
import { ServiceUnavailableState } from '@/components/features/platform';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Gated } from '@/components/features/capabilities/gated';
import { useCompute } from '@/hooks';
import { useToast } from '@/hooks/use-toast';
import { vmStateName } from '@/lib/compute-state';
import { resolveDynamicId } from '@/utils/dynamic-route';

const GET_SNAPSHOT_OP = 'GET /api/v1/compute/vms/{id}/snapshots/{snapshotId}';

interface ErrorLike {
  message?: string;
  status?: number;
  code?: number | string;
}

// isNotFound reads a 404 from a refused response or a thrown error.
function isNotFound(err: ErrorLike | undefined): boolean {
  if (!err) return false;
  if (err.status === 404 || err.code === 404 || err.code === '404') return true;
  return /not found/i.test(err.message ?? '');
}

function formatGB(bytes: number | undefined): string {
  return `${((bytes ?? 0) / 1024 ** 3).toFixed(1)} GB`;
}

/**
 * SnapshotDetailClient shows one VM snapshot, read through the SDK's
 * ComputeService.getSnapshot. The snapshot id comes from the path (the static
 * export serves the __placeholder__ page) and the VM id from the ?vm= query.
 */
export default function SnapshotDetailClient() {
  const snapshotId = resolveDynamicId(useParams(), usePathname(), 'snapshots', 'snapshotId');
  const vmId = useSearchParams().get('vm') ?? '';
  const compute = useCompute();
  const { toast } = useToast();

  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [notFound, setNotFound] = useState(false);
  const [loading, setLoading] = useState(false);
  // Set when the server answers that compute is not configured on this node.
  const [unavailable, setUnavailable] = useState(false);

  const load = useCallback(async () => {
    if (!vmId || !snapshotId) return;
    setLoading(true);
    let failure: ErrorLike | undefined;
    let found: Snapshot | undefined;
    try {
      const res = await compute.getSnapshot({ vmId, snapshotId });
      if (res.success === false) {
        failure = (res.error as ErrorLike | undefined) ?? { message: 'request refused' };
      } else {
        found = res.data?.snapshot;
      }
    } catch (err) {
      failure = (err as ErrorLike) ?? { message: String(err) };
    } finally {
      setLoading(false);
    }

    if (failure && isServiceNotConfigured(failure)) {
      setSnapshot(null);
      setNotFound(false);
      setUnavailable(true);
      return;
    }
    setUnavailable(false);
    if (failure) {
      toast({
        title: 'Error loading snapshot',
        description: failure.message ?? 'request failed',
        variant: 'destructive',
      });
      setSnapshot(null);
      setNotFound(isNotFound(failure));
      return;
    }
    setSnapshot(found ?? null);
    setNotFound(!found);
  }, [compute, snapshotId, toast, vmId]);

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vmId, snapshotId]);

  if (!vmId) {
    return (
      <div className="space-y-4 p-6">
        <p>No VM given</p>
        <Link href="/compute/snapshots" className="text-primary underline">
          Back to snapshots
        </Link>
      </div>
    );
  }

  const name = snapshot?.config?.name || snapshot?.id || snapshotId;

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        {snapshot ? <h1 className="text-2xl font-bold">{name}</h1> : <h1 className="text-2xl font-bold">Snapshot</h1>}
        <Gated op={GET_SNAPSHOT_OP}>
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
        </Gated>
      </div>

      {unavailable && (
        <ServiceUnavailableState
          service="Compute"
          description="The compute service is not configured on this node. In this topology, VMs and containers run on compute nodes; this node does not host workloads."
        />
      )}

      {notFound && <p>Snapshot not found</p>}

      {snapshot && (
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-muted-foreground">Description</dt>
              <dd>{snapshot.config?.description || '-'}</dd>
              <dt className="text-muted-foreground">Created</dt>
              <dd>{snapshot.createdAt ? new Date(snapshot.createdAt).toLocaleString() : '-'}</dd>
              <dt className="text-muted-foreground">Size</dt>
              <dd>{formatGB(snapshot.sizeBytes)}</dd>
              <dt className="text-muted-foreground">VM</dt>
              <dd>
                <Link href={`/compute/vms/${encodeURIComponent(snapshot.vmId || vmId)}`} className="text-primary underline">
                  {snapshot.vmId || vmId}
                </Link>
              </dd>
              <dt className="text-muted-foreground">VM state</dt>
              <dd>{vmStateName(snapshot.vmState) ?? '-'}</dd>
              <dt className="text-muted-foreground">Memory snapshot</dt>
              <dd>{snapshot.config?.memorySnapshot ? 'Yes' : 'No'}</dd>
              <dt className="text-muted-foreground">Disk snapshot</dt>
              <dd>{snapshot.config?.diskSnapshot ? 'Yes' : 'No'}</dd>
            </dl>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
