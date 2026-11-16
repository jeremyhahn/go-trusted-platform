'use client';

import { useMemo, useState } from 'react';
import { Plus, RefreshCw, HardDrive, Settings, AlertCircle, Loader2 } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ServiceUnavailableState } from '@/components/features/platform';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import { usePXE, useApi, useToast, useReportedGateways } from '@/hooks';
import type { PXEDeviceInfo } from 'trusted-platform-sdk';

export default function PXEBootPage() {
  const { toast } = useToast();
  const pxe = usePXE();
  const [createOpen, setCreateOpen] = useState(false);
  const [createMac, setCreateMac] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Fetch PXE devices
  const {
    data: devicesData,
    isLoading: devicesLoading,
    error: devicesError,
    refetch: refetchDevices,
  } = useApi(
    () => pxe.listDevices(),
    [],
    {
      onError: (err) => {
        // A structured 503 means PXE is not wired on this node (e.g.
        // a control plane, where PXE lives on the gateway role) —
        // rendered as an informational state, not an error toast.
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading devices',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch PXE status
  const {
    data: statusData,
    isLoading: statusLoading,
    error: statusError,
    refetch: refetchStatus,
  } = useApi(
    () => pxe.getStatus(),
    [],
    {
      onError: (err) => {
        if (isServiceNotConfigured(err)) {
          return;
        }
        toast({
          title: 'Error loading PXE status',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  const pxeUnavailable =
    isServiceNotConfigured(devicesError) || isServiceNotConfigured(statusError);

  // When PXE is not served by this node, show where it IS served: the
  // control plane's gateway telemetry cache carries each gatewayd's PXE
  // state. Only fetched in that branch — a node that serves PXE has no
  // use for the fleet table.
  const { gateways: gatewayReports, isLoading: gatewayReportsLoading } =
    useReportedGateways({ enabled: pxeUnavailable });

  const devices = devicesData?.devices || [];
  const status = statusData?.status || null;
  const isLoading = devicesLoading || statusLoading;
  const error = devicesError || statusError;

  const fetchData = () => {
    refetchDevices();
    refetchStatus();
  };

  // Calculate stats from devices
  const stats = useMemo(() => {
    const stateGroups = devices.reduce((acc: Record<string, number>, device: PXEDeviceInfo) => {
      const state = device.state || 'UNKNOWN';
      acc[state] = (acc[state] || 0) + 1;
      return acc;
    }, {});

    return {
      total: devices.length,
      discovered: stateGroups['DISCOVERED'] || 0,
      booting: stateGroups['BOOTING'] || 0,
      installing: stateGroups['INSTALLING'] || 0,
      enrolled: stateGroups['ENROLLED'] || 0,
      authorized: stateGroups['AUTHORIZED'] || 0,
      failed: stateGroups['FAILED'] || 0,
      quarantined: stateGroups['QUARANTINED'] || 0,
    };
  }, [devices]);

  const getStateColor = (state: string) => {
    switch (state) {
      case 'AUTHORIZED':
        return 'bg-green-500/10 text-green-500 border-green-500/20';
      case 'ENROLLED':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
      case 'INSTALLING':
      case 'BOOTING':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'FAILED':
      case 'QUARANTINED':
        return 'bg-red-500/10 text-red-500 border-red-500/20';
      default:
        return 'bg-gray-500/10 text-gray-500 border-gray-500/20';
    }
  };

  // PXE is not configured on this node — the expected state on a
  // control plane, where PXE is served by the gateway role. Show where
  // it DOES run instead of an error.
  if (pxeUnavailable) {
    return (
      <div className="container mx-auto py-6 space-y-6">
        <div>
          <h1 className="text-3xl font-bold">PXE Boot</h1>
          <p className="text-muted-foreground mt-1">
            Network boot provisioning and device management
          </p>
        </div>
        <ServiceUnavailableState
          service="PXE"
          description="The PXE service is not configured on this node. In this topology, PXE network boot is served by the gateway role (gatewayd's pxe service section); gateways report their PXE state here via telemetry."
        />
        <Card>
          <CardHeader>
            <CardTitle>Reported Gateways</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {gatewayReportsLoading ? (
              <p className="text-sm text-muted-foreground">
                <Loader2 className="inline-block h-4 w-4 animate-spin mr-2" />
                Loading reported gateways…
              </p>
            ) : gatewayReports.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No gatewayd processes have reported yet.
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Gateway</TableHead>
                    <TableHead>PXE Status</TableHead>
                    <TableHead>Listen Address</TableHead>
                    <TableHead>Boots Served</TableHead>
                    <TableHead>Last Report</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {gatewayReports.map((g) => (
                    <TableRow key={g.gateway_id}>
                      <TableCell>{g.hostname ?? g.gateway_id}</TableCell>
                      <TableCell>
                        <Badge
                          className={
                            g.pxe?.status === 'running'
                              ? 'bg-green-500/10 text-green-500 border-green-500/20'
                              : 'bg-gray-500/10 text-gray-500 border-gray-500/20'
                          }
                        >
                          {g.pxe?.status ?? 'unknown'}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {g.pxe?.listen_address ?? '—'}
                      </TableCell>
                      <TableCell>{g.pxe?.boots_served ?? 0}</TableCell>
                      <TableCell className="text-xs">
                        {new Date(g.reported_at).toLocaleString()}
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

  // Show error state
  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading PXE Boot</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchData}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Show loading state
  if (isLoading && devices.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading PXE boot data...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">PXE Boot</h1>
          <p className="text-muted-foreground mt-1">
            Network boot provisioning and device management
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchData} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Register Device
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Register PXE Device</DialogTitle>
            <DialogDescription>
              Pre-authorize a device by MAC address for PXE boot.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="pxe-mac">MAC Address *</Label>
              <Input
                id="pxe-mac"
                value={createMac}
                onChange={(e) => setCreateMac(e.target.value)}
                placeholder="aa:bb:cc:11:22:33"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!createMac || createSubmitting}
              onClick={async () => {
                setCreateSubmitting(true);
                try {
                  await pxe.registerDevice({ macAddress: createMac });
                  toast({ title: 'Device registered', variant: 'success' });
                  setCreateOpen(false);
                  setCreateMac('');
                  refetchDevices();
                } catch (err) {
                  toast({
                    title: 'Failed to register device',
                    description: err instanceof Error ? err.message : 'Unknown error',
                    variant: 'destructive',
                  });
                } finally {
                  setCreateSubmitting(false);
                }
              }}
            >
              {createSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Register
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="grid gap-4 md:grid-cols-5">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Devices</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Authorized</div>
          <div className="text-3xl font-bold mt-2 text-green-500">
            {stats.authorized}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Enrolled</div>
          <div className="text-3xl font-bold mt-2 text-blue-500">
            {stats.enrolled}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Provisioning</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">
            {stats.booting + stats.installing}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Failed</div>
          <div className="text-3xl font-bold mt-2 text-red-500">
            {stats.failed + stats.quarantined}
          </div>
        </div>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                PXE Service Status
              </CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            {status ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Status</span>
                  <Badge
                    variant="outline"
                    className={
                      status.running
                        ? 'bg-green-500/10 text-green-500 border-green-500/20'
                        : 'bg-red-500/10 text-red-500 border-red-500/20'
                    }
                  >
                    {status.running ? 'Running' : 'Stopped'}
                  </Badge>
                </div>
                {status.deviceCount !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Device Count</span>
                    <Badge variant="outline">
                      {status.deviceCount}
                    </Badge>
                  </div>
                )}
                {status.quarantineVlan !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Quarantine VLAN</span>
                    <Badge variant="outline">
                      VLAN {status.quarantineVlan}
                    </Badge>
                  </div>
                )}
                {status.provisioningVlan !== undefined && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Provisioning VLAN</span>
                    <Badge variant="outline">
                      VLAN {status.provisioningVlan}
                    </Badge>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-center text-muted-foreground py-8">
                PXE service status not available
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <HardDrive className="h-5 w-5" />
              Recent Devices
            </CardTitle>
          </CardHeader>
          <CardContent>
            {isLoading ? (
              <div className="flex items-center justify-center h-32">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : devices.length === 0 ? (
              <p className="text-center text-muted-foreground py-8">
                No devices found
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>MAC Address</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Updated</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {devices.slice(0, 5).map((device: PXEDeviceInfo) => (
                    <TableRow key={device.id}>
                      <TableCell className="font-mono text-sm">
                        {device.macAddress}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={getStateColor(device.state)}
                        >
                          {device.state}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm">
                        {device.updatedAt ? formatDistanceToNow(new Date(device.updatedAt), {
                          addSuffix: true,
                        }) : '-'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Devices</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>MAC Address</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Current VLAN</TableHead>
                  <TableHead>Target VLAN</TableHead>
                  <TableHead>Certificate</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Updated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {devices.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="text-center text-muted-foreground"
                    >
                      No devices found
                    </TableCell>
                  </TableRow>
                ) : (
                  devices.map((device: PXEDeviceInfo) => (
                    <TableRow key={device.id}>
                      <TableCell className="font-mono text-sm">
                        {device.macAddress}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={getStateColor(device.state)}
                        >
                          {device.state}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        {device.currentVlan ? (
                          <Badge variant="secondary">VLAN {device.currentVlan}</Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        {device.targetVlan ? (
                          <Badge variant="secondary">VLAN {device.targetVlan}</Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {device.certificateSerial ? device.certificateSerial.substring(0, 16) + '...' : '-'}
                      </TableCell>
                      <TableCell className="text-sm">
                        {device.createdAt ? formatDistanceToNow(new Date(device.createdAt), {
                          addSuffix: true,
                        }) : '-'}
                      </TableCell>
                      <TableCell className="text-sm">
                        {device.updatedAt ? formatDistanceToNow(new Date(device.updatedAt), {
                          addSuffix: true,
                        }) : '-'}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
