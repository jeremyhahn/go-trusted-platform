'use client';

/**
 * Containers Page
 *
 * Displays all containers with filtering and management capabilities.
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
import { ContainerTable } from '@/components/features/compute/container-table';
import { ContainerForm } from '@/components/features/compute/container-form';
import { useCompute, useApi, useToast } from '@/hooks';
import type { Container } from '@/types/infrastructure';

export default function ContainersPage() {
  const { toast } = useToast();
  const compute = useCompute();
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [formOpen, setFormOpen] = useState(false);

  // Fetch containers using SDK
  const {
    data: containersData,
    isLoading: loading,
    refetch: fetchContainers,
  } = useApi(
    () => compute.listContainers(),
    [],
    {
      onError: (err) => {
        toast({
          title: 'Error',
          description: `Failed to fetch containers: ${err.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK containers to local Container type for UI compatibility
  const containers: Container[] = useMemo(() => {
    if (!containersData?.containers) return [];
    return containersData.containers.map((container) => ({
      id: container.id,
      name: container.config?.name || container.id,
      image: container.config?.image || '',
      status: (container.state?.toLowerCase() || 'creating') as Container['status'],
      createdAt: container.createdAt || new Date().toISOString(),
      ports: container.config?.ports?.map((p) => ({
        container: p.containerPort,
        host: p.hostPort,
        protocol: (p.protocol?.toLowerCase() || 'tcp') as 'tcp' | 'udp',
      })) || [],
    }));
  }, [containersData]);

  // Filter containers by status
  const filteredContainers = useMemo(() => {
    if (statusFilter === 'all') {
      return containers;
    }
    return containers.filter((container) => container.status === statusFilter);
  }, [statusFilter, containers]);

  const stats = {
    total: containers.length,
    running: containers.filter((c) => c.status === 'running').length,
    stopped: containers.filter((c) => c.status === 'stopped').length,
    error: containers.filter((c) => c.status === 'error').length,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Containers</h1>
          <p className="text-muted-foreground mt-1">
            Manage your container instances
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => fetchContainers()}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setFormOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Container
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total</div>
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
          <div className="text-sm font-medium text-muted-foreground">Error</div>
          <div className="text-3xl font-bold mt-2 text-red-500">{stats.error}</div>
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
              <SelectItem value="creating">Creating</SelectItem>
              <SelectItem value="error">Error</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <ContainerTable containers={filteredContainers} onRefresh={() => fetchContainers()} />
      )}

      <ContainerForm
        open={formOpen}
        onOpenChange={setFormOpen}
        onSuccess={() => fetchContainers()}
      />
    </div>
  );
}
