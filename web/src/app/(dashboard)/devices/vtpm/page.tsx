'use client';

/**
 * vTPM List Page
 *
 * Display all vTPM instances with filtering and management capabilities.
 * Uses the trusted-platform-sdk for API interactions.
 */

import { useState, useMemo } from 'react';
import { Plus, Filter } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Input } from '@/components/ui/input';
import { VTPMTable } from '@/components/features/devices/vtpm-table';
import { VTPMForm } from '@/components/features/devices/vtpm-form';
import { useVTPM, useApi, useToast } from '@/hooks';
import type { VTPM, VTPMFilters } from '@/types/device';

export default function VTPMPage() {
  const { toast } = useToast();
  const vtpm = useVTPM();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [filters, setFilters] = useState<VTPMFilters>({});

  // Fetch vTPM bundles using SDK
  const {
    data: bundlesData,
    isLoading,
    refetch: fetchVTPMs,
  } = useApi(
    () => vtpm.listBundles({
      options: {
        limit: 100,
      },
    }),
    [filters.state, filters.vmId, filters.search],
    {
      onError: (err) => {
        toast({
          title: 'Error',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK bundles to local VTPM type for UI compatibility
  const vtpms: VTPM[] = useMemo(() => {
    if (!bundlesData?.bundles) return [];
    let result = bundlesData.bundles.map((bundle) => ({
      id: bundle.id,
      name: bundle.manifest?.hostname || bundle.id,
      state: 'active' as VTPM['state'],
      vmId: bundle.id,
      vmName: bundle.manifest?.hostname,
      tpmVersion: '2.0',
      createdAt: bundle.createdAt || new Date().toISOString(),
      updatedAt: bundle.createdAt,
      ekCertificate: bundle.manifest?.ekCertificate ? JSON.stringify(bundle.manifest.ekCertificate) : undefined,
      aikCertificate: undefined,
      pcrBanks: undefined,
      pcrProfile: '',
    }));

    // Apply client-side search filter
    if (filters.search) {
      const search = filters.search.toLowerCase();
      result = result.filter((v) =>
        v.name.toLowerCase().includes(search) ||
        v.id.toLowerCase().includes(search)
      );
    }

    // Apply client-side vmId filter
    if (filters.vmId) {
      result = result.filter((v) => v.vmId?.includes(filters.vmId!));
    }

    return result;
  }, [bundlesData, filters.search, filters.vmId]);

  const handleSuccess = () => {
    setIsDialogOpen(false);
    fetchVTPMs();
  };

  const handleFilterChange = (key: keyof VTPMFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Virtual TPM (vTPM)</h1>
          <p className="text-muted-foreground">
            Manage virtual TPM instances for VMs and containers
          </p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create vTPM
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Create New vTPM Instance</DialogTitle>
              <DialogDescription>
                Create a virtual TPM for a VM or container
              </DialogDescription>
            </DialogHeader>
            <VTPMForm
              onSuccess={handleSuccess}
              onCancel={() => setIsDialogOpen(false)}
            />
          </DialogContent>
        </Dialog>
      </div>

      <div className="flex items-center gap-4 rounded-lg border border-border bg-card p-4">
        <Filter className="h-5 w-5 text-muted-foreground" />
        <div className="flex flex-1 items-center gap-4">
          <Input
            placeholder="Search vTPM instances..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.state || 'all'}
            onValueChange={(value) => handleFilterChange('state', value === 'all' ? '' : value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All states" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All states</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="sealed">Sealed</SelectItem>
              <SelectItem value="migrating">Migrating</SelectItem>
              <SelectItem value="suspended">Suspended</SelectItem>
            </SelectContent>
          </Select>
          <Input
            placeholder="Filter by VM ID..."
            value={filters.vmId || ''}
            onChange={(e) => handleFilterChange('vmId', e.target.value)}
            className="max-w-xs"
          />
          {(filters.state || filters.vmId || filters.search) && (
            <Button
              variant="ghost"
              onClick={() => setFilters({})}
            >
              Clear filters
            </Button>
          )}
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="text-center">
            <div className="inline-block h-8 w-8 animate-spin rounded-full border-4 border-solid border-current border-r-transparent motion-reduce:animate-[spin_1.5s_linear_infinite]" />
            <p className="mt-2 text-sm text-muted-foreground">Loading vTPM instances...</p>
          </div>
        </div>
      ) : (
        <VTPMTable vtpms={vtpms} onVTPMChange={() => fetchVTPMs()} />
      )}
    </div>
  );
}
