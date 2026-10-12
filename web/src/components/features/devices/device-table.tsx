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
import { useAttestation, useDevice, useMutation } from '@/hooks';
import type { DeviceReport } from 'trusted-platform-sdk';
import { clockBadge, freshnessBadge, verdictBadge, type FleetReportsState } from '@/lib/attestation-report';
import { DEVICE_TOGGLE_UNAVAILABLE } from '@/lib/device-lifecycle';
import type { Device } from '@/types/device';

/** How the fleet's attestation reports were fetched, for the Attestation column. */
interface DeviceTableProps {
  devices: Device[];
  onDeviceChange?: () => void;
  /** The collector's cached reports keyed by device id (#428); absent devices were never collected */
  reports?: Map<string, DeviceReport>;
  reportsState?: FleetReportsState;
}

export function DeviceTable({ devices, onDeviceChange, reports, reportsState = 'ready' }: DeviceTableProps) {
  const router = useRouter();
  const { toast } = useToast();
  const deviceService = useDevice();
  const attestation = useAttestation();
  const [loadingId, setLoadingId] = useState<string | null>(null);

  // "Refresh attestation" enqueues a collection with the control plane's
  // collector (202, never a quote); the verdict and its age come back through
  // the report the Attestation column renders (#226, #428). The control it
  // replaced attested THIS control plane's own TPM and reported success for
  // the selected device.
  const refreshMutation = useMutation(
    async (id: string) => {
      return await attestation.refreshDeviceReport(id);
    },
    {
      onSuccess: (accepted) => {
        if (accepted?.enqueued) {
          toast({
            title: 'Collection enqueued',
            description: 'The collector will attest the device on its next pass; the report re-reads with the new age.',
          });
        } else {
          toast({
            title: 'Refresh not accepted',
            description: 'The collector answered without enqueuing the request',
            variant: 'destructive',
          });
        }
        onDeviceChange?.();
      },
      onError: (error) => {
        toast({ title: 'Refresh failed', description: error.message, variant: 'destructive' });
      },
    }
  );

  // Enable / Disable Device is not wired to anything real yet.
  //
  // The mutation this replaces had no body: it returned
  // `{ data: {}, error: undefined, success: true }` without sending a
  // request, and the success handler then toasted "Device disabled
  // successfully". An operator was told a live machine had been cut off
  // when nothing had been sent anywhere. There is no server-side
  // operator lifecycle transition to call instead — see #250 — so the
  // control is disabled until one lands.

  const deleteMutation = useMutation(
    async (id: string) => {
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

  const handleDelete = async (device: Device) => {
    if (!confirm(`Are you sure you want to delete ${device.name}?`)) {
      return;
    }

    setLoadingId(device.id);
    try {
      await deleteMutation.mutateAsync(device.id);
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
            <TableHead>Attestation</TableHead>
            <TableHead>Last Seen</TableHead>
            <TableHead>Status</TableHead>
            <TableHead className="text-right">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {devices.length === 0 ? (
            <TableRow>
              <TableCell colSpan={7} className="text-center text-muted-foreground">
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
                      {device.tpm.hasAKCert ? (
                        <Badge variant="outline" title="An attestation certificate is enrolled; quotes can be verified">
                          AK cert
                        </Badge>
                      ) : (
                        <Badge
                          variant="destructive"
                          title="No attestation certificate is enrolled; quotes from this device are denied (#404)"
                        >
                          No AK cert
                        </Badge>
                      )}
                    </div>
                  ) : (
                    <span className="text-sm text-muted-foreground">No TPM</span>
                  )}
                </TableCell>
                <TableCell>
                  <FleetReportCell report={reports?.get(device.id)} state={reportsState} />
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
                          disabled={reportsState === 'not-configured' || refreshMutation.isLoading}
                          title="Enqueue an out-of-cycle collection; the verdict arrives when the collector has attested the device"
                          onClick={() => refreshMutation.mutate(device.id)}
                        >
                          <Shield className="mr-2 h-4 w-4" />
                          Refresh attestation
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuItem
                        disabled
                        title={DEVICE_TOGGLE_UNAVAILABLE}
                        className="cursor-not-allowed"
                      >
                        {device.status === 'disabled' ? (
                          <>
                            <Power className="mr-2 h-4 w-4" />
                            Enable Device (unavailable)
                          </>
                        ) : (
                          <>
                            <BanIcon className="mr-2 h-4 w-4" />
                            Disable Device (unavailable)
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

/**
 * The fleet table's Attestation column: the verdict WITH its age, or the
 * distinct "never collected" / "reporting not configured" states. A device
 * absent from the collector's cache has never been collected, which is not a
 * failed verdict and is not rendered as one.
 */
function FleetReportCell({ report, state }: { report?: DeviceReport; state: FleetReportsState }) {
  if (state === 'loading') {
    return <span className="text-xs text-muted-foreground">Loading…</span>;
  }
  if (state === 'not-configured') {
    return (
      <span className="text-xs text-muted-foreground" title="The attestation reporting service is not configured on this node">
        Reporting not configured
      </span>
    );
  }
  if (state === 'error') {
    return <span className="text-xs text-muted-foreground">Reports unavailable</span>;
  }
  if (!report) {
    return (
      <Badge
        variant="outline"
        title="The collector has not reached this device yet; this is not a failed verdict"
        data-testid="fleet-never-collected"
      >
        Never collected
      </Badge>
    );
  }
  const verdict = verdictBadge(report);
  const freshness = freshnessBadge(report);
  const clock = clockBadge(report);
  return (
    <div className="flex flex-wrap items-center gap-1" data-testid="fleet-report" data-fresh={report.fresh ? 'true' : 'false'}>
      <Badge variant={verdict.variant} title={verdict.title}>
        {verdict.label}
      </Badge>
      <Badge variant={freshness.variant} title={freshness.title}>
        {freshness.label}
      </Badge>
      {report.time_synced === false && (
        <Badge variant={clock.variant} title={clock.title} data-testid="fleet-clock-unsynced">
          {clock.label}
        </Badge>
      )}
    </div>
  );
}
