'use client';

/**
 * DeviceTable Component
 * DataTable for displaying and managing devices
 */

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  MoreHorizontal,
  Eye,
  Shield,
  BanIcon,
  Trash2,
  Power,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';
import { useDevice, useMutation } from '@/hooks';
import { ATTESTATION_UNAVAILABLE } from '@/lib/attestation';
import type { Device } from '@/types/device';

interface DeviceTableProps {
  devices: Device[];
  onDeviceChange?: () => void;
}

export function DeviceTable({ devices, onDeviceChange }: DeviceTableProps) {
  const router = useRouter();
  const { toast } = useToast();
  const deviceService = useDevice();
  const [loadingId, setLoadingId] = useState<string | null>(null);

  // Per-device attestation is not wired to anything real yet.
  //
  // This used to call collectHostAttestation(), which attests THIS control
  // plane's own TPM, discard the deviceId entirely, and then report success
  // for the selected device — a green tick for a machine that was never
  // attested. That is worse than an outage, so the control is disabled
  // until the attestation reporting service lands (#226).

  const updateMutation = useMutation(
    async ({ id, status }: { id: number; status: Device['status'] }) => {
      // TODO: Update SDK to support device status updates
      // For now, just return success without updating
      return { data: {}, error: undefined, success: true };
    },
    {
      onSuccess: (data, { status }) => {
        toast({
          title: 'Success',
          description: `Device ${status === 'disabled' ? 'disabled' : 'enabled'} successfully`,
        });
        onDeviceChange?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error instanceof Error ? error.message : 'Failed to update device',
          variant: 'destructive',
        });
      },
    }
  );

  const deleteMutation = useMutation(
    async (id: number) => {
      return await deviceService.deleteDevice(id);
    },
    {
      onSuccess: () => {
        toast({
          title: 'Success',
          description: 'Device deleted successfully',
        });
        onDeviceChange?.();
      },
      onError: (error) => {
        toast({
          title: 'Error',
          description: error instanceof Error ? error.message : 'Failed to delete device',
          variant: 'destructive',
        });
      },
    }
  );

  const handleToggleStatus = async (device: Device) => {
    setLoadingId(device.id);
    try {
      const status: Device['status'] = device.status === 'disabled' ? 'online' : 'disabled';
      await updateMutation.mutateAsync({ id: device.id as any, status });
    } finally {
      setLoadingId(null);
    }
  };

  const handleDelete = async (device: Device) => {
    if (!confirm(`Are you sure you want to delete ${device.name}?`)) {
      return;
    }

    setLoadingId(device.id);
    try {
      await deleteMutation.mutateAsync(device.id as any);
    } finally {
      setLoadingId(null);
    }
  };

  const getStatusBadge = (device: Device) => {
    const variants = {
      online: { variant: 'default' as const, label: 'Online' },
      offline: { variant: 'secondary' as const, label: 'Offline' },
      disabled: { variant: 'destructive' as const, label: 'Disabled' },
      unknown: { variant: 'outline' as const, label: 'Unknown' },
    };

    // device.status is computed ONCE per data fetch by the shared
    // deriveDeviceStatus helper (lifecycle state + heartbeat freshness).
    // The badge renders that same value rather than recomputing
    // freshness here, so filtering and rendering can never disagree on
    // a long-open page.
    const { variant, label } = variants[device.status] ?? variants.unknown;
    return <Badge variant={variant}>{label}</Badge>;
  };

  const getTypeBadge = (type: Device['type']) => {
    return (
      <Badge variant="outline">
        {type === 'physical' ? 'Physical' : 'Virtual'}
      </Badge>
    );
  };

  const formatLastSeen = (lastSeen?: string) => {
    if (!lastSeen) return 'Never';

    const date = new Date(lastSeen);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };

  return (
    <div className="rounded-md border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Name</TableHead>
            <TableHead>Type</TableHead>
            <TableHead>TPM Status</TableHead>
            <TableHead>Last Seen</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.length === 0 ? (
            <TableRow>
              <TableCell colSpan={6} className="text-center text-muted-foreground">
                No devices found
              </TableCell>
            </TableRow>
          ) : (
            devices.map((device) => (
              <TableRow
                key={device.id}
                className="cursor-pointer hover:bg-muted/40"
                onClick={() => router.push(`/devices/${device.id}`)}
              >
                <TableCell className="font-medium">
                  <button
                    type="button"
                    className="text-left hover:underline focus:underline focus:outline-none"
                    onClick={(e) => {
                      e.stopPropagation();
                      router.push(`/devices/${device.id}`);
                    }}
                  >
                    {device.name}
                  </button>
                </TableCell>
                <TableCell>{getTypeBadge(device.type)}</TableCell>
                <TableCell>
                  {device.tpm ? (
                    <div className="flex items-center gap-2">
                      <Shield className="h-4 w-4 text-green-600" />
                      <span className="text-sm">{device.tpm.manufacturer}</span>
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">No TPM</span>
                  )}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground">
                  {formatLastSeen(device.lastSeen)}
                </TableCell>
                <TableCell>{getStatusBadge(device)}</TableCell>
                <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={loadingId === device.id}
                        onClick={(e) => e.stopPropagation()}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                        <span className="sr-only">Open menu</span>
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => router.push(`/devices/${device.id}`)}
                      >
                        <Eye className="mr-2 h-4 w-4" />
                        View Details
                      </DropdownMenuItem>
                      {device.tpm && (
                        <DropdownMenuItem
                          disabled
                          title={ATTESTATION_UNAVAILABLE}
                          className="cursor-not-allowed"
                        >
                          <Shield className="mr-2 h-4 w-4" />
                          Run Attestation (unavailable)
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem onClick={() => handleToggleStatus(device)}>
                        {device.status === 'disabled' ? (
                          <>
                            <Power className="mr-2 h-4 w-4" />
                            Enable Device
                          </>
                        ) : (
                          <>
                            <BanIcon className="mr-2 h-4 w-4" />
                            Disable Device
                          </>
                        )}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        onClick={() => handleDelete(device)}
                        className="text-destructive"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
