'use client';

import { useMemo, useState } from 'react';
import { Plus, RefreshCw, MoreHorizontal, RotateCcw, Trash2, Copy, Download, AlertCircle, Loader2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ServiceUnavailableState } from '@/components/features/platform';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { useApi, useCompute, useMutation, useToast } from '@/hooks';
import type { Snapshot, VM } from 'trusted-platform-sdk';

// Extended snapshot type with source name
interface SnapshotWithSource extends Snapshot {
  sourceName: string;
  sourceType: 'vm';
}

const sourceTypeColors = {
  vm: 'bg-purple-500/10 text-purple-500 border-purple-500/20',
};

export default function SnapshotsPage() {
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const { toast } = useToast();
  const compute = useCompute();

  // Fetch all VMs to get their snapshots
  const {
    data: vmsData,
    isLoading: vmsLoading,
    error: vmsError,
    refetch: refetchVMs,
  } = useApi(
    () => compute.listVMs(),
    [],
    {
      onError: (err) => {
        // A structured 503 means compute is not wired on this node —
        // rendered as an informational state below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading VMs',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Extract VMs from response
  const vms = useMemo(() => vmsData?.vms || [], [vmsData]);

  // Fetch snapshots for all VMs
  const {
    data: snapshotsData,
    isLoading: snapshotsLoading,
    error: snapshotsError,
    refetch: refetchSnapshots,
  } = useApi(
    async () => {
      if (!vms.length) {
        return { success: true, data: { snapshots: [] as SnapshotWithSource[] } };
      }

      // Fetch snapshots for all VMs in parallel
      const snapshotPromises = vms.map((vm: VM) =>
        compute.listSnapshots(vm.id).then((response) => ({
          vmId: vm.id,
          vmName: vm.config?.name || vm.id,
          snapshots: response.data?.snapshots || [],
        }))
      );

      const results = await Promise.all(snapshotPromises);

      // Flatten and enrich snapshots with VM name
      const allSnapshots: SnapshotWithSource[] = results.flatMap((result) =>
        result.snapshots.map((snapshot: Snapshot) => ({
          ...snapshot,
          sourceName: result.vmName,
          sourceType: 'vm' as const,
        }))
      );

      return { success: true, data: { snapshots: allSnapshots } };
    },
    [vms],
    {
      enabled: vms.length > 0,
      onError: (err) => {
        toast({
          title: 'Error loading snapshots',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const snapshots = useMemo(() => snapshotsData?.snapshots || [], [snapshotsData]);

  // Filter snapshots based on status
  const filteredSnapshots = useMemo(() => {
    let filtered = snapshots;

    // Note: SDK snapshots don't have a status field, so we can't filter by status
    // All snapshots are considered 'available' once created

    return filtered;
  }, [snapshots]);

  // Delete snapshot mutation
  const deleteSnapshotMutation = useMutation(
    async ({ vmId, snapshotId }: { vmId: string; snapshotId: string }) => {
      return compute.deleteSnapshot({ vmId, snapshotId });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Snapshot deleted',
          description: 'The snapshot has been deleted successfully',
          variant: 'success',
        });
        refetchSnapshots();
      },
      onError: (error) => {
        toast({
          title: 'Error deleting snapshot',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Restore snapshot mutation
  const restoreSnapshotMutation = useMutation(
    async ({ vmId, snapshotId }: { vmId: string; snapshotId: string }) => {
      return compute.restoreSnapshot({ vmId, snapshotId });
    },
    {
      onSuccess: () => {
        toast({
          title: 'Restore initiated',
          description: 'The VM is being restored from the snapshot',
          variant: 'success',
        });
        refetchVMs();
      },
      onError: (error) => {
        toast({
          title: 'Error restoring snapshot',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );

  const handleRestore = (snapshot: SnapshotWithSource) => {
    if (window.confirm(`Are you sure you want to restore from snapshot ${snapshot.config?.name || snapshot.id}?`)) {
      restoreSnapshotMutation.mutate({ vmId: snapshot.vmId, snapshotId: snapshot.id });
    }
  };

  const handleDelete = (snapshot: SnapshotWithSource) => {
    if (window.confirm(`Are you sure you want to delete snapshot ${snapshot.config?.name || snapshot.id}?`)) {
      deleteSnapshotMutation.mutate({ vmId: snapshot.vmId, snapshotId: snapshot.id });
    }
  };

  const handleClone = (snapshot: SnapshotWithSource) => {
    toast({
      title: 'Feature Not Available',
      description: 'Snapshot cloning is not yet implemented in the API',
      variant: 'default',
    });
  };

  const handleExport = (snapshot: SnapshotWithSource) => {
    toast({
      title: 'Feature Not Available',
      description: 'Snapshot export is not yet implemented in the API',
      variant: 'default',
    });
  };

  const handleRefresh = () => {
    refetchVMs();
    refetchSnapshots();
  };

  const formatSize = (bytes: number) => {
    const mb = bytes / (1024 * 1024);
    if (mb >= 1024) {
      return `${(mb / 1024).toFixed(1)} GB`;
    }
    return `${mb.toFixed(0)} MB`;
  };

  const stats = useMemo(
    () => ({
      total: snapshots.length,
      vmSnapshots: snapshots.length, // All snapshots are VM snapshots
    }),
    [snapshots]
  );

  const totalSize = useMemo(
    () => snapshots.reduce((acc, s) => acc + (s.sizeBytes || 0), 0),
    [snapshots]
  );

  const isLoading = vmsLoading || snapshotsLoading;

  // Compute not wired on this node (structured 503) — informational
  // state, not an error.
  if (isServiceNotConfigured(vmsError)) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Snapshots</h1>
          <p className="text-muted-foreground mt-1">
            Manage VM snapshots for backup and recovery
          </p>
        </div>
        <ServiceUnavailableState
          service="Compute"
          description="The compute service is not configured on this node. In this topology, VMs and containers run on compute nodes; this node does not host workloads."
        />
      </div>
    );
  }

  // Show error state
  if (vmsError || snapshotsError) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Snapshots</AlertTitle>
          <AlertDescription>
            {vmsError?.message || snapshotsError?.message}
            <Button variant="outline" size="sm" className="ml-4" onClick={handleRefresh}>
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Snapshots</h1>
          <p className="text-muted-foreground mt-1">
            Manage VM snapshots for backup and recovery
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={handleRefresh} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button
            onClick={() =>
              toast({
                title: 'Feature Not Available',
                description: 'Create snapshot from this page coming soon. Use VM details page to create snapshots.',
                variant: 'default',
              })
            }
          >
            <Plus className="mr-2 h-4 w-4" />
            Create Snapshot
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Snapshots</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">VM Snapshots</div>
          <div className="text-3xl font-bold mt-2 text-purple-500">{stats.vmSnapshots}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Size</div>
          <div className="text-3xl font-bold mt-2">{formatSize(totalSize)}</div>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : filteredSnapshots.length === 0 ? (
        <Alert>
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>No Snapshots Found</AlertTitle>
          <AlertDescription>
            {vms.length === 0
              ? 'No VMs are currently running. Create a VM first to take snapshots.'
              : 'No snapshots have been created yet. Navigate to a VM details page to create a snapshot.'}
          </AlertDescription>
        </Alert>
      ) : (
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Source VM</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>VM State</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredSnapshots.map((snapshot) => (
                <TableRow key={`${snapshot.vmId}-${snapshot.id}`}>
                  <TableCell>
                    <div>
                      <div className="font-medium">{snapshot.config?.name || snapshot.id}</div>
                      {snapshot.config?.description && (
                        <div className="text-sm text-muted-foreground">{snapshot.config.description}</div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{snapshot.sourceName}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={sourceTypeColors.vm}>
                      VM
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {snapshot.vmState || 'UNKNOWN'}
                    </Badge>
                  </TableCell>
                  <TableCell>{formatSize(snapshot.sizeBytes || 0)}</TableCell>
                  <TableCell>
                    {snapshot.createdAt
                      ? formatDistanceToNow(new Date(snapshot.createdAt), { addSuffix: true })
                      : 'Unknown'}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={
                            restoreSnapshotMutation.isLoading || deleteSnapshotMutation.isLoading
                          }
                        >
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem onClick={() => handleRestore(snapshot)}>
                          <RotateCcw className="mr-2 h-4 w-4" />
                          Restore
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleClone(snapshot)}>
                          <Copy className="mr-2 h-4 w-4" />
                          Clone to New Instance
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleExport(snapshot)}>
                          <Download className="mr-2 h-4 w-4" />
                          Export
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          onClick={() => handleDelete(snapshot)}
                          className="text-destructive"
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
