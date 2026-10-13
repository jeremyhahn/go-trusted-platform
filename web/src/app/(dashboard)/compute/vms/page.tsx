'use client';

/**
 * Virtual Machines Page
 *
 * Displays all VMs with filtering and management capabilities.
 * Uses the trusted-platform-sdk for API interactions.
 */

import { useState, useMemo } from 'react';
import { Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { VMTable } from '@/components/features/compute/vm-table';
import { VMForm } from '@/components/features/compute/vm-form';
import { ServiceUnavailableState } from '@/components/features/platform';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { useCompute, useApi, useToast } from '@/hooks';
import type { VM } from '@/types/infrastructure';
import { vmStatus } from '@/lib/compute-state';

export default function VMsPage() {
  const { toast } = useToast();
  const compute = useCompute();
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [formOpen, setFormOpen] = useState(false);

  // Fetch VMs using SDK
  const {
    data: vmsData,
    isLoading: loading,
    error: vmsError,
    refetch: fetchVMs,
  } = useApi(
    () => compute.listVMs(),
    [],
    {
      onError: (err) => {
        // A structured 503 means compute is not wired on this node
        // (e.g. a control plane) — rendered as an informational state
        // below, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error',
          description: `Failed to fetch VMs: ${err.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  const computeUnavailable = isServiceNotConfigured(vmsError);

  // Transform SDK VMs to local VM type for UI compatibility
  const vms: VM[] = useMemo(() => {
    if (!vmsData?.vms) return [];
    return vmsData.vms.map((vm) => ({
      id: vm.id,
      name: vm.config?.name || vm.id,
      status: vmStatus(vm.state),
      vcpus: vm.config?.cpu?.cores || 0,
      memoryMB: vm.config?.memory?.sizeMb || 0,
      storageMB: (vm.config?.disks?.[0]?.sizeGb || 0) * 1024, // Convert GB to MB
      ipAddress: undefined, // IP is assigned at runtime, not in config
      createdAt: vm.createdAt || new Date().toISOString(),
    }));
  }, [vmsData]);

  // Filter VMs by status
  const filteredVMs = useMemo(() => {
    if (statusFilter === 'all') {
      return vms;
    }
    return vms.filter((vm) => vm.status === statusFilter);
  }, [statusFilter, vms]);

  const stats = {
    total: vms.length,
    running: vms.filter((vm) => vm.status === 'running').length,
    stopped: vms.filter((vm) => vm.status === 'stopped').length,
    suspended: vms.filter((vm) => vm.status === 'suspended').length,
  };

  if (computeUnavailable) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-3xl font-bold">Virtual Machines</h1>
          <p className="text-muted-foreground mt-1">
            Manage your virtual machine instances
          </p>
        </div>
        <ServiceUnavailableState
          service="Compute"
          description="The compute service is not configured on this node. In this topology, VMs and containers run on compute nodes; this node does not host workloads."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Virtual Machines</h1>
          <p className="text-muted-foreground mt-1">
            Manage your virtual machine instances
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={() => fetchVMs()} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setFormOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create VM
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total VMs</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Running</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.running}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Stopped</div>
          <div className="text-3xl font-bold mt-2 text-gray-500">{stats.stopped}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Suspended</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">
            {stats.suspended}
          </div>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <label className="text-sm font-medium">Filter by status:</label>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="running">Running</SelectItem>
              <SelectItem value="stopped">Stopped</SelectItem>
              <SelectItem value="suspended">Suspended</SelectItem>
              <SelectItem value="creating">Creating</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <VMTable vms={filteredVMs} onRefresh={() => fetchVMs()} />
      )}

      <VMForm open={formOpen} onOpenChange={setFormOpen} onSuccess={() => fetchVMs()} />
    </div>
  );
}
