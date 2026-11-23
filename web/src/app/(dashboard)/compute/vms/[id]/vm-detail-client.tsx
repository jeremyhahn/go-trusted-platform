'use client';

import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  Play,
  Square,
  RotateCw,
  Trash2,
  RefreshCw,
  Pause,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import type { Snapshot, VM } from 'trusted-platform-sdk';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { VMMetricsCard } from '@/components/features/compute/vm-metrics';
import { VMDisksCard } from '@/components/features/compute/vm-disks-card';
import { Gated } from '@/components/features/capabilities/gated';
import { VMMigrateButton } from '@/components/features/compute/vm-migrate-dialog';
import { useCompute, useMutation, useToast, type MutationError } from '@/hooks';
import type { VMMetrics as WebVMMetrics } from '@/types/infrastructure';
import { vmStatus } from '@/lib/compute-state';

const statusColors = {
  running: 'bg-green-500/10 text-green-500 border-green-500/20',
  stopped: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
  suspended: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
  creating: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
};

export default function VMDetailPage() {
  const params = useParams();
  const pathname = usePathname();
  const router = useRouter();
  const vmId = resolveDynamicId(params, pathname, 'vms');
  const [vm, setVM] = useState<(VM & { status: ReturnType<typeof vmStatus> }) | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [snapshots, setSnapshots] = useState<Snapshot[]>([]);
  const [snapshotsError, setSnapshotsError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const compute = useCompute();
  const { toast } = useToast();

  const loadErrorText = (err: unknown): string => {
    if (typeof err === 'string') return err;
    if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
      return err.message;
    }
    return 'the control plane refused the request';
  };

  const fetchVM = async () => {
    if (!vmId) {
      setLoadError('No VM ID in the address');
      return;
    }
    try {
      const response = await compute.getVM(vmId);
      if (response.success === false || !response.data?.vm) {
        setLoadError(loadErrorText(response.error ?? 'the control plane returned no VM'));
        return;
      }
      const loaded: VM = response.data.vm;
      setVM({ ...loaded, status: vmStatus(loaded.state) });
      setLoadError(null);
    } catch (error) {
      setLoadError(loadErrorText(error));
    }
  };

  const fetchSnapshots = async () => {
    if (!vmId) return;
    try {
      const response = await compute.listSnapshots(vmId);
      if (response.success === false) {
        setSnapshotsError(loadErrorText(response.error));
        return;
      }
      setSnapshots(response.data?.snapshots ?? []);
      setSnapshotsError(null);
    } catch (error) {
      setSnapshotsError(loadErrorText(error));
    }
  };

  useEffect(() => {
    fetchVM();
    fetchSnapshots();
    if (!vmId) return;
    const interval = setInterval(fetchVM, 5000);
    return () => clearInterval(interval);
  }, [vmId]);

  const startVMMutation = useMutation(
    (vmId: string) => compute.startVM(vmId),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM started successfully',
        });
        setActionLoading(false);
        fetchVM();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to start VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const stopVMMutation = useMutation(
    (vmId: string) => compute.stopVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM stopped successfully',
        });
        setActionLoading(false);
        fetchVM();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to stop VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const rebootVMMutation = useMutation(
    (vmId: string) => compute.rebootVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM rebooted successfully',
        });
        setActionLoading(false);
        fetchVM();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to reboot VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const suspendVMMutation = useMutation(
    (vmId: string) => compute.suspendVM(vmId),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM suspended',
        });
        setActionLoading(false);
        fetchVM();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to suspend VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const resumeVMMutation = useMutation(
    (vmId: string) => compute.resumeVM(vmId),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM resumed',
        });
        setActionLoading(false);
        fetchVM();
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to resume VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const deleteVMMutation = useMutation(
    (vmId: string) => compute.deleteVM({ id: vmId }),
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'VM deleted successfully',
        });
        router.push('/compute/vms');
      },
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to delete VM: ${error.message}`,
          variant: 'destructive',
        });
        setActionLoading(false);
      },
    }
  );

  const handleStart = () => {
    setActionLoading(true);
    startVMMutation.mutate(vmId);
  };

  const handleStop = () => {
    setActionLoading(true);
    stopVMMutation.mutate(vmId);
  };

  const handleReboot = () => {
    setActionLoading(true);
    rebootVMMutation.mutate(vmId);
  };

  const handleSuspend = () => {
    setActionLoading(true);
    suspendVMMutation.mutate(vmId);
  };

  const handleResume = () => {
    setActionLoading(true);
    resumeVMMutation.mutate(vmId);
  };

  const handleDelete = () => {
    setActionLoading(true);
    deleteVMMutation.mutate(vmId);
  };


  if (!vm && loadError) {
    return (
      <Alert variant="destructive" data-testid="vm-detail-error">
        <AlertDescription>Could not load the VM: {loadError}</AlertDescription>
      </Alert>
    );
  }

  if (!vm) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const vmName = vm.config?.name || vm.id;
  const disks = vm.config?.disks ?? [];
  const snapshotName = (s: Snapshot) => s.config?.name || (s as Snapshot & { name?: string }).name || s.id;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{vmName}</h1>
            <p className="text-muted-foreground mt-1">Virtual Machine Details</p>
          </div>
        </div>
        <div className="flex gap-2">
          {vm.status !== 'running' && (
            <Gated op="POST /api/v1/compute/vms/{id}/start">
              <Button
                variant="outline"
                onClick={handleStart}
                disabled={actionLoading}
              >
                <Play className="mr-2 h-4 w-4" />
                Start
              </Button>
            </Gated>
          )}
          {vm.status === 'running' && (
            <>
              <Gated op="POST /api/v1/compute/vms/{id}/stop">
                <Button
                  variant="outline"
                  onClick={handleStop}
                  disabled={actionLoading}
                >
                  <Square className="mr-2 h-4 w-4" />
                  Stop
                </Button>
              </Gated>
              <Gated op="POST /api/v1/compute/vms/{id}/suspend">
                <Button
                  variant="outline"
                  onClick={handleSuspend}
                  disabled={actionLoading}
                >
                  <Pause className="mr-2 h-4 w-4" />
                  Suspend
                </Button>
              </Gated>
              <Gated op="POST /api/v1/compute/vms/{id}/reboot">
                <Button
                  variant="outline"
                  onClick={handleReboot}
                  disabled={actionLoading}
                >
                  <RotateCw className="mr-2 h-4 w-4" />
                  Reboot
                </Button>
              </Gated>
              <VMMigrateButton vmId={vmId} disabled={actionLoading} onMigrated={fetchVM} />
            </>
          )}
          {vm.status === 'suspended' && (
            <Gated op="POST /api/v1/compute/vms/{id}/resume">
              <Button
                variant="outline"
                onClick={handleResume}
                disabled={actionLoading}
              >
                <Play className="mr-2 h-4 w-4" />
                Resume
              </Button>
            </Gated>
          )}
          <Gated op="DELETE /api/v1/compute/vms/{id}">
            <Button
              variant="destructive"
              onClick={handleDelete}
              disabled={actionLoading}
            >
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </Button>
          </Gated>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>VM Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4" data-testid="vm-info">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Status</span>
              <Badge variant="outline" className={statusColors[vm.status as keyof typeof statusColors]}>
                {vm.status}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">CPU</span>
              <span className="font-medium">
                {vm.config?.cpu?.cores != null ? `${vm.config.cpu.cores} vCPUs` : '-'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Memory</span>
              <span className="font-medium">
                {vm.config?.memory?.sizeMb != null ? `${vm.config.memory.sizeMb} MB` : '-'}
              </span>
            </div>
            <div className="flex items-start justify-between gap-4">
              <span className="text-muted-foreground">Disks</span>
              <span className="text-right font-mono text-sm">
                {disks.length === 0
                  ? '-'
                  : disks.map((d) => (
                      <span key={d.id ?? d.path} className="block">
                        {d.path}
                        {d.sizeGb != null ? ` (${d.sizeGb} GB)` : ''}
                      </span>
                    ))}
              </span>
            </div>
            {vm.hostId && (
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Host</span>
                <span className="font-mono text-sm">{vm.hostId}</span>
              </div>
            )}
            {vm.createdAt && (
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Created</span>
                <span className="font-medium">
                  {formatDistanceToNow(new Date(vm.createdAt), { addSuffix: true })}
                </span>
              </div>
            )}
          </CardContent>
        </Card>

        {vm.metrics && <VMMetricsCard metrics={vm.metrics as unknown as WebVMMetrics} />}
      </div>

      <VMDisksCard
        vmId={vmId}
        disks={disks.map((d) => ({
          id: d.id ?? d.path,
          path: d.path,
          sizeMB: (d.sizeGb ?? 0) * 1024,
          // The SDK DiskType is the image format (raw, qcow2, ...); config disks are never CD-ROMs.
          type: 'disk' as const,
          readonly: Boolean(d.readonly),
        }))}
        onChanged={fetchVM}
      />

      <Card>
        <CardHeader>
          <CardTitle>Snapshots</CardTitle>
        </CardHeader>
        <CardContent>
          {snapshotsError ? (
            <p className="text-center text-muted-foreground py-8" data-testid="vm-snapshots-error">
              Could not list snapshots: {snapshotsError}
            </p>
          ) : snapshots.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">No snapshots</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {snapshots.map((snapshot) => (
                  <TableRow key={snapshot.id}>
                    <TableCell className="font-medium">
                      <Link
                        href={`/compute/snapshots/${encodeURIComponent(snapshot.id)}?vm=${encodeURIComponent(vmId)}`}
                        className="hover:underline"
                      >
                        {snapshotName(snapshot)}
                      </Link>
                    </TableCell>
                    <TableCell>
                      {snapshot.sizeBytes != null ? formatStorage(Math.round(snapshot.sizeBytes / (1024 * 1024))) : '-'}
                    </TableCell>
                    <TableCell>
                      {snapshot.createdAt
                        ? formatDistanceToNow(new Date(snapshot.createdAt), { addSuffix: true })
                        : '-'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function formatStorage(mb: number): string {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
}
