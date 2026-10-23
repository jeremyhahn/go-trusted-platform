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
import { useAttestation, useDevice, useApi } from '@/hooks';
import type { DeviceReport } from 'trusted-platform-sdk';
import { fleetReportsState } from '@/lib/attestation-report';
import { deriveDeviceStatus } from '@/lib/device-status';
import type { Device, DeviceFilters } from '@/types/device';
// The wire type comes from the SDK. A local copy of it is a second declaration
// of the same wire, and the two drift — this file's copy carried `id: number`
// for a field the server sends as a string (#329, #378).
import type { Device as SDKDevice } from 'trusted-platform-sdk';

export default function DevicesPage() {
  const { toast } = useToast();
  const deviceService = useDevice();
  const attestation = useAttestation();
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
    const transformedDevices = rawDevices.map((device: SDKDevice): Device => {
      // ACME enroll-01 registered devices carry the hostname-derived
      // identifier in `serial` (e.g. "node-01-gw-01") and the hardware
      // model in `model` (e.g. "SuperMicro X10"). Operators expect the
      // Name column to be the unique node identifier; fall back to model
      // only when no serial was supplied (manual UI registration where
      // serial is optional).
      // The SDK now declares the wire names for the fields it models (#329),
      // so attest_pub and ek_cert are read straight off `device`. This cast
      // remains for the fields the SDK type does NOT declare — `state` and
      // `last_heartbeat_at` — which the REST surface sends and no SDK type
      // carries yet.
      const anyDev = device as SDKDevice & {
        last_heartbeat_at?: string;
        state?: string;
      };
      const attestPub = device.attest_pub;
      const attestCert = device.attest_cert;
      const ekCert = device.ek_cert;
      return {
        id: String(device.id),
        name: device.serial || device.model || 'Unknown',
        type: 'physical' as const, // SDK doesn't have device type yet
        // Status derives from lifecycle state + heartbeat freshness so
        // the status FILTER agrees with what the table renders.
        status: deriveDeviceStatus(anyDev.state ?? '', anyDev.last_heartbeat_at),
        state: anyDev.state || undefined,
        serial: device.serial || undefined,
        model: device.model || undefined,
        // Liveness comes exclusively from the heartbeat timestamp the
        // node reports over mTLS — updated_at moves on any write and
        // would fake freshness.
        lastSeen: anyDev.last_heartbeat_at || undefined,
        registeredAt: device.created_at || '',

        tpm: attestPub ? {
          manufacturer: device.model || 'Unknown',
          version: '2.0',
          firmwareVersion: '1.0',
          hasEK: !!ekCert,
          hasSRK: false,
          hasAKCert: !!attestCert,
        } : undefined,
      };
    });

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

  // The collector's cached verdicts for the fleet, joined to devices by id
  // (#428). A 503 means reporting is not configured on this node; a device
  // absent from the list has never been collected.
  const {
    data: reportsData,
    error: reportsError,
    isLoading: reportsLoading,
    refetch: refetchReports,
  } = useApi(() => attestation.listDeviceReports(), []);
  const reports = useMemo(() => {
    const map = new Map<string, DeviceReport>();
    for (const report of reportsData?.reports ?? []) {
      map.set(String(report.device_id), report);
    }
    return map;
  }, [reportsData]);
  const reportsState = fleetReportsState(reportsLoading, reportsError);

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
              <SelectItem value="unknown">Unknown</SelectItem>
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
        <DeviceTable
          devices={devices}
          onDeviceChange={() => {
            refetch();
            refetchReports();
          }}
          reports={reports}
          reportsState={reportsState}
        />
      )}
    </div>
  );
}
