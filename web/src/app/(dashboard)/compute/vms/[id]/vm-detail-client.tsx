'use client';

import { useState, useEffect } from 'react';
import { useParams, usePathname, useRouter } from 'next/navigation';
import { resolveDynamicId } from '@/utils/dynamic-route';
import {
  ArrowLeft,
  Play,
  Square,
  RotateCw,
  Copy,
  Trash2,
  Camera,
  RefreshCw,
  Pause,
  ShieldCheck,
} from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useVMAttestationVerify } from '@/hooks';
import type { VerifyVMAttestationResponse } from 'trusted-platform-sdk';
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
import { VMMetricsCard } from '@/components/features/compute/vm-metrics';
import { useCompute, useMutation, useToast, type MutationError } from '@/hooks';
import type { VMDetail } from '@/types/infrastructure';
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
  const [vm, setVM] = useState<VMDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const compute = useCompute();
  const { toast } = useToast();
  const verifyAttestation = useVMAttestationVerify(vmId);
  const [verifyConfirmOpen, setVerifyConfirmOpen] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyVMAttestationResponse | null>(null);

  const handleVerifyAttestation = async () => {
    setVerifyConfirmOpen(false);
    setActionLoading(true);
    try {
      setVerifyResult(await verifyAttestation());
    } catch (error) {
      toast({
        title: 'Error',
        description: `Failed to verify VM attestation: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setActionLoading(false);
    }
  };

  const fetchVM = async () => {
    if (!vmId) {
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      const response = await compute.getVM(vmId);
      if (response.success && response.data) {
        // SDK returns { vm: VM }, but we need VMDetail
        // For now, cast to VMDetail - proper type mapping would be handled by backend
        setVM({
          ...(response.data.vm as unknown as VMDetail),
          status: vmStatus(response.data.vm.state),
        });
      }
    } catch (error) {
      toast({
        title: 'Error',
        description: `Failed to fetch VM details: ${error instanceof Error ? error.message : 'Unknown error'}`,
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVM();
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

  // TODO: Suspend/Resume functionality not available in SDK yet
  // SDK only provides start/stop/reboot operations
  // Placeholder mutations for future implementation
  const suspendVMMutation = useMutation(
    async (vmId: string) => {
      throw new Error('Suspend operation not yet implemented in SDK');
    },
    {
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
    async (vmId: string) => {
      throw new Error('Resume operation not yet implemented in SDK');
    },
    {
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

  // TODO: Clone functionality not available in SDK yet
  // This would require VM snapshot + restore to new VM functionality
  const cloneVMMutation = useMutation(
    async ({ vmId, name }: { vmId: string; name: string }) => {
      throw new Error('Clone operation not yet implemented in SDK');
    },
    {
      onError: (error: MutationError) => {
        toast({
          title: 'Error',
          description: `Failed to clone VM: ${error.message}`,
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

  const handleClone = () => {
    const name = prompt('Enter name for cloned VM:');
    if (!name) return;

    setActionLoading(true);
    cloneVMMutation.mutate({ vmId: vmId, name });
  };

  if (loading || !vm) {
    return (
      <div className="flex items-center justify-center h-64">
        <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  const formatMemory = (mb: number) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`);
  const formatStorage = (mb: number) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.back()}>
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold">{vm.name}</h1>
            <p className="text-muted-foreground mt-1">Virtual Machine Details</p>
          </div>
        </div>
        <div className="flex gap-2">
          {vm.status !== 'running' && (
            <Button
              variant="outline"
              onClick={handleStart}
              disabled={actionLoading}
            >
              <Play className="mr-2 h-4 w-4" />
              Start
            </Button>
          )}
          {vm.status === 'running' && (
            <>
              <Button
                variant="outline"
                onClick={handleStop}
                disabled={actionLoading}
              >
                <Square className="mr-2 h-4 w-4" />
                Stop
              </Button>
              <Button
                variant="outline"
                onClick={handleSuspend}
                disabled={actionLoading}
              >
                <Pause className="mr-2 h-4 w-4" />
                Suspend
              </Button>
              <Button
                variant="outline"
                onClick={handleReboot}
                disabled={actionLoading}
              >
                <RotateCw className="mr-2 h-4 w-4" />
                Reboot
              </Button>
            </>
          )}
          {vm.status === 'suspended' && (
            <Button
              variant="outline"
              onClick={handleResume}
              disabled={actionLoading}
            >
              <Play className="mr-2 h-4 w-4" />
              Resume
            </Button>
          )}
          <Button
            variant="outline"
            onClick={() => setVerifyConfirmOpen(true)}
            disabled={actionLoading}
          >
            <ShieldCheck className="mr-2 h-4 w-4" />
            Verify Attestation
          </Button>
          <Button variant="outline" onClick={handleClone} disabled={actionLoading}>
            <Copy className="mr-2 h-4 w-4" />
            Clone
          </Button>
          <Button
            variant="destructive"
            onClick={handleDelete}
            disabled={actionLoading}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>VM Information</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Status</span>
              <Badge variant="outline" className={statusColors[vm.status]}>
                {vm.status}
              </Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">vCPUs</span>
              <span className="font-medium">{vm.vcpus}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Memory</span>
              <span className="font-medium">{formatMemory(vm.memoryMB)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Storage</span>
              <span className="font-medium">{formatStorage(vm.storageMB)}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">IP Address</span>
              <span className="font-mono text-sm">{vm.ipAddress || '-'}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">OS Type</span>
              <span className="font-medium capitalize">{vm.osType}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-muted-foreground">Created</span>
              <span className="font-medium">
                {formatDistanceToNow(new Date(vm.createdAt), { addSuffix: true })}
              </span>
            </div>
          </CardContent>
        </Card>

        <VMMetricsCard metrics={vm.metrics} />
      </div>

      {verifyResult && (
        <Card data-testid="vm-verify-result">
          <CardHeader>
            <CardTitle>Attestation Verification</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="font-medium">
              {verifyResult.verified ? 'Attestation verified' : 'Attestation not verified'}
            </p>
            {verifyResult.message && (
              <p className="text-muted-foreground">{verifyResult.message}</p>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog open={verifyConfirmOpen} onOpenChange={setVerifyConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Verify VM attestation?</DialogTitle>
            <DialogDescription>
              This requests a fresh TPM quote from {vm.name} and verifies it.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setVerifyConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => void handleVerifyAttestation()}>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle>Snapshots</CardTitle>
            <Button size="sm">
              <Camera className="mr-2 h-4 w-4" />
              Create Snapshot
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {vm.snapshots.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">No snapshots</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Size</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {vm.snapshots.map((snapshot) => (
                  <TableRow key={snapshot.id}>
                    <TableCell className="font-medium">{snapshot.name}</TableCell>
                    <TableCell>{formatStorage(snapshot.sizeMB)}</TableCell>
                    <TableCell>
                      {formatDistanceToNow(new Date(snapshot.createdAt), {
                        addSuffix: true,
                      })}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm">
                        Restore
                      </Button>
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
