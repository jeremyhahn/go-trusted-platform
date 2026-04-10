'use client';

/**
 * Devices List Page
 * Display all registered devices with filtering and management capabilities
 *
 * Uses SDK hooks:
 * - useDevice(): Access to DeviceService
 * - useApi(): Declarative data fetching with dependency tracking
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
import { DeviceTable } from '@/components/features/devices/device-table';
import { DeviceForm } from '@/components/features/devices/device-form';
import { useToast } from '@/hooks/use-toast';
import { useDevice, useApi } from '@/hooks';
import type { Device, DeviceFilters } from '@/types/device';

// SDK Device type shape (from sdk/javascript/src/types/device.ts)
interface SDKDevice {
  id: number;
  model?: string;
  serial: string;
  attestPub?: string;
  ekCert?: string;
  createdAt: string;
  updatedAt: string;
}

export default function DevicesPage() {
  const { toast } = useToast();
  const deviceService = useDevice();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [filters, setFilters] = useState<DeviceFilters>({});

  // Use the SDK's useApi hook for data fetching
  // The hook automatically refetches when filters change (via deps array)
  const {
    data: devicesResponse,
    isLoading,
    refetch,
  } = useApi(
    () => deviceService.listDevices({
      page: 1,
      pageSize: 100,
      // Note: The SDK may need filter parameters added to ListDevicesRequest
      // For now, we fetch all and filter client-side
    }),
    [filters], // Refetch when filters change
    {
      onError: (err) => {
        toast({
          title: 'Error',
          description: err.message || 'Failed to fetch devices',
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK Device to local Device type and apply client-side filters
  const devices: Device[] = useMemo(() => {
    const rawDevices: SDKDevice[] = devicesResponse?.devices ?? [];

    // First transform SDK devices to local Device type
    const transformedDevices = rawDevices.map((device: SDKDevice): Device => ({
      id: String(device.id),
      name: device.model || device.serial || 'Unknown',
      type: 'physical' as const, // SDK doesn't have device type yet
      status: 'online' as const, // SDK doesn't have device status yet
      serial: device.serial || undefined,
      lastSeen: device.updatedAt || undefined,
      registeredAt: device.createdAt,
      tpm: device.attestPub ? {
        manufacturer: 'Unknown',
        version: '2.0',
        firmwareVersion: '1.0',
        hasEK: !!device.ekCert,
        hasSRK: false,
      } : undefined,
    }));

    // Apply client-side filtering
    return transformedDevices.filter((device: Device) => {
      // Search filter
      if (filters.search) {
        const search = filters.search.toLowerCase();
        const name = device.name.toLowerCase();
        const serial = (device.serial || '').toLowerCase();
        if (!name.includes(search) && !serial.includes(search)) {
          return false;
        }
      }
      // Type filter
      if (filters.type && device.type !== filters.type) {
        return false;
      }
      // Status filter
      if (filters.status && device.status !== filters.status) {
        return false;
      }
      return true;
    });
  }, [devicesResponse, filters]);

  const handleSuccess = () => {
    setIsDialogOpen(false);
    refetch();
  };

  const handleFilterChange = (key: keyof DeviceFilters, value: string) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value || undefined,
    }));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Devices</h1>
          <p className="text-muted-foreground">
            Manage physical and virtual devices with TPM support
          </p>
        </div>
        <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Register Device
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl">
            <DialogHeader>
              <DialogTitle>Register New Device</DialogTitle>
              <DialogDescription>
                Add a new physical or virtual device to the platform
              </DialogDescription>
            </DialogHeader>
            <DeviceForm
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
            placeholder="Search devices..."
            value={filters.search || ''}
            onChange={(e) => handleFilterChange('search', e.target.value)}
            className="max-w-sm"
          />
          <Select
            value={filters.type || 'all'}
            onValueChange={(value) => handleFilterChange('type', value === 'all' ? '' : value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All types</SelectItem>
              <SelectItem value="physical">Physical</SelectItem>
              <SelectItem value="virtual">Virtual</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={filters.status || 'all'}
            onValueChange={(value) => handleFilterChange('status', value === 'all' ? '' : value)}
          >
            <SelectTrigger className="w-40">
              <SelectValue placeholder="All statuses" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              <SelectItem value="online">Online</SelectItem>
              <SelectItem value="offline">Offline</SelectItem>
              <SelectItem value="disabled">Disabled</SelectItem>
            </SelectContent>
          </Select>
          {(filters.type || filters.status || filters.search) && (
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
            <p className="mt-2 text-sm text-muted-foreground">Loading devices...</p>
          </div>
        </div>
      ) : (
        <DeviceTable devices={devices} onDeviceChange={refetch} />
      )}
    </div>
  );
}
