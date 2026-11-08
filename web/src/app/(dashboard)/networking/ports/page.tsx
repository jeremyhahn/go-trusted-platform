'use client';

import { useState, useMemo, useCallback } from 'react';
import { Plus, RefreshCw, Cable, Wifi, WifiOff, AlertCircle, Loader2 } from 'lucide-react';
import { ColumnDef } from '@tanstack/react-table';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { DataTable, createSelectColumn } from '@/components/ui/data-table';
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header';
import { DataTableRowActions } from '@/components/ui/data-table-row-actions';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { useSDN, useApi } from '@/hooks';
import type { Port, PortType } from 'trusted-platform-sdk';
import { portState, readUint64, type SDNPortState } from '@/lib/sdn-wire';

// Types for SDN Port management
interface SDNPort {
  id: string;
  name: string;
  number: number;
  switch: string;
  macAddress: string;
  status: SDNPortState;
  speed: string;
  duplex: 'full' | 'half' | 'auto';
  vlanId?: number;
  rxPackets: number;
  txPackets: number;
  rxBytes: number;
  txBytes: number;
  rxErrors: number;
  txErrors: number;
  lastSeen: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export default function SDNPortsPage() {
  const { toast } = useToast();
  const sdn = useSDN();
  const [selectedBridgeId, setSelectedBridgeId] = useState<string>('');
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createType, setCreateType] = useState<PortType>('PORT_TYPE_INTERNAL');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Fetch bridges to get the first bridge ID
  const {
    data: bridgesData,
    isLoading: bridgesLoading,
    error: bridgesError,
    refetch: refetchBridges,
  } = useApi(
    () => sdn.listBridges(),
    [],
    {
      onSuccess: (data) => {
        if (data.bridges && data.bridges.length > 0 && !selectedBridgeId) {
          setSelectedBridgeId(data.bridges[0].id);
        }
      },
      onError: (err) => {
        toast({
          title: 'Error loading bridges',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Fetch ports for the selected bridge
  const {
    data: portsData,
    isLoading: portsLoading,
    error: portsError,
    refetch: refetchPorts,
  } = useApi(
    () => selectedBridgeId ? sdn.listPorts({ bridgeId: selectedBridgeId }) : Promise.resolve({ success: true, data: { ports: [] } }),
    [selectedBridgeId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading ports',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK ports to UI format
  const ports = useMemo<SDNPort[]>(() => {
    if (!portsData?.ports) return [];
    return portsData.ports.map((port: Port, index: number) => ({
      id: port.id,
      name: port.config?.name || `port-${index}`,
      number: index + 1,
      switch: selectedBridgeId,
      macAddress: port.config?.macAddress || 'N/A',
      status: portState(port.status),
      speed: 'N/A',
      duplex: 'auto' as const,
      vlanId: port.config?.vlan,
      rxPackets: readUint64(port.stats?.packetsReceived),
      txPackets: readUint64(port.stats?.packetsSent),
      rxBytes: readUint64(port.stats?.bytesReceived),
      txBytes: readUint64(port.stats?.bytesSent),
      rxErrors: readUint64(port.stats?.errors),
      txErrors: readUint64(port.stats?.errors),
      lastSeen: port.updatedAt || new Date().toISOString(),
    }));
  }, [portsData, selectedBridgeId]);

  const isLoading = bridgesLoading || portsLoading;
  const error = bridgesError || portsError;

  const fetchPorts = useCallback(() => {
    refetchBridges();
    if (selectedBridgeId) {
      refetchPorts();
    }
  }, [refetchBridges, refetchPorts, selectedBridgeId]);

  const handleViewPort = (port: SDNPort) => {
    toast({
      title: 'View Port',
      description: `Viewing details for port ${port.name}`,
    });
  };

  const handleEditPort = (port: SDNPort) => {
    toast({
      title: 'Edit Port',
      description: `Editing port ${port.name}`,
    });
  };

  const handleTogglePort = (port: SDNPort) => {
    toast({
      title: 'Toggle Port',
      description: `Toggling port ${port.name} is not yet implemented`,
    });
  };

  const handleDeletePort = async (port: SDNPort) => {
    if (!selectedBridgeId) return;
    try {
      await sdn.deletePort(selectedBridgeId, port.id);
      toast({
        title: 'Port Deleted',
        description: `Port ${port.name} has been deleted`,
      });
      refetchPorts();
    } catch (err) {
      toast({
        title: 'Error deleting port',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const columns: ColumnDef<SDNPort>[] = [
    createSelectColumn<SDNPort>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Cable className="h-4 w-4 text-muted-foreground" />
          <span className="font-medium">{row.getValue('name')}</span>
        </div>
      ),
    },
    {
      accessorKey: 'number',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Port #" />
      ),
      cell: ({ row }) => (
        <span className="font-mono">{row.getValue('number')}</span>
      ),
    },
    {
      accessorKey: 'switch',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Switch" />
      ),
      cell: ({ row }) => (
        <Badge variant="outline">{row.getValue('switch')}</Badge>
      ),
    },
    {
      accessorKey: 'macAddress',
      header: 'MAC Address',
      cell: ({ row }) => (
        <span className="font-mono text-sm">{row.getValue('macAddress')}</span>
      ),
    },
    {
      accessorKey: 'status',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Status" />
      ),
      cell: ({ row }) => {
        const status = row.getValue('status') as string;
        const statusConfig = {
          up: {
            icon: Wifi,
            className: 'bg-green-500/10 text-green-500 border-green-500/20',
          },
          down: {
            icon: WifiOff,
            className: 'bg-red-500/10 text-red-500 border-red-500/20',
          },
          blocked: {
            icon: WifiOff,
            className: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
          },
        };
        const config = statusConfig[status as keyof typeof statusConfig];
        const Icon = config.icon;
        return (
          <Badge variant="outline" className={config.className}>
            <Icon className="h-3 w-3 mr-1" />
            {status}
          </Badge>
        );
      },
      filterFn: (row, id, value) => {
        return value.includes(row.getValue(id));
      },
    },
    {
      accessorKey: 'speed',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Speed" />
      ),
    },
    {
      accessorKey: 'vlanId',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="VLAN" />
      ),
      cell: ({ row }) => {
        const vlanId = row.getValue('vlanId') as number | undefined;
        return vlanId ? (
          <Badge variant="secondary">VLAN {vlanId}</Badge>
        ) : (
          <span className="text-muted-foreground">-</span>
        );
      },
    },
    {
      accessorKey: 'rxBytes',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="RX Traffic" />
      ),
      cell: ({ row }) => formatBytes(row.getValue('rxBytes')),
    },
    {
      accessorKey: 'txBytes',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="TX Traffic" />
      ),
      cell: ({ row }) => formatBytes(row.getValue('txBytes')),
    },
    {
      id: 'actions',
      cell: ({ row }) => (
        <DataTableRowActions
          row={row.original}
          actions={[
            { label: 'View Details', onClick: handleViewPort },
            { label: 'Edit', onClick: handleEditPort },
            {
              label: row.original.status === 'up' ? 'Disable' : 'Enable',
              onClick: handleTogglePort,
            },
            {
              label: 'Delete',
              onClick: handleDeletePort,
              variant: 'destructive',
              separator: true,
            },
          ]}
        />
      ),
    },
  ];

  const stats = {
    total: ports.length,
    up: ports.filter((p) => p.status === 'up').length,
    down: ports.filter((p) => p.status === 'down').length,
    blocked: ports.filter((p) => p.status === 'blocked').length,
  };

  const handleBulkDelete = async (selectedPorts: SDNPort[]) => {
    if (!selectedBridgeId) return;
    try {
      await Promise.all(
        selectedPorts.map((p) => sdn.deletePort(selectedBridgeId, p.id))
      );
      toast({
        title: 'Ports Deleted',
        description: `${selectedPorts.length} ports have been deleted`,
      });
      refetchPorts();
    } catch (err) {
      toast({
        title: 'Error deleting ports',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  // Show error state
  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Ports</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchPorts}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Show loading state
  if (isLoading && ports.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading ports...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">SDN Ports</h1>
          <p className="text-muted-foreground mt-1">
            Manage switch ports and network interfaces
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchPorts} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)} disabled={!selectedBridgeId}>
            <Plus className="mr-2 h-4 w-4" />
            Add Port
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Port</DialogTitle>
            <DialogDescription>
              Add a port to bridge {selectedBridgeId || 'unknown'}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="port-name">Name *</Label>
              <Input
                id="port-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="eth0"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="port-type">Type</Label>
              <Select value={createType} onValueChange={(v) => setCreateType(v as PortType)}>
                <SelectTrigger id="port-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="PORT_TYPE_INTERNAL">internal</SelectItem>
                  <SelectItem value="PORT_TYPE_PHYSICAL">physical</SelectItem>
                  <SelectItem value="PORT_TYPE_TAP">tap</SelectItem>
                  <SelectItem value="PORT_TYPE_VETH">veth</SelectItem>
                  <SelectItem value="PORT_TYPE_VXLAN">vxlan</SelectItem>
                  <SelectItem value="PORT_TYPE_GRE">gre</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!createName || createSubmitting || !selectedBridgeId}
              onClick={async () => {
                setCreateSubmitting(true);
                try {
                  await sdn.addPort({
                    bridgeId: selectedBridgeId,
                    config: { name: createName, type: createType },
                  });
                  toast({ title: 'Port added', variant: 'success' });
                  setCreateOpen(false);
                  setCreateName('');
                  refetchPorts();
                } catch (err) {
                  toast({
                    title: 'Failed to add port',
                    description: err instanceof Error ? err.message : 'Unknown error',
                    variant: 'destructive',
                  });
                } finally {
                  setCreateSubmitting(false);
                }
              }}
            >
              {createSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Add
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Ports</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Up</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.up}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Down</div>
          <div className="text-3xl font-bold mt-2 text-red-500">{stats.down}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Blocked</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">{stats.blocked}</div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cable className="h-5 w-5" />
            Network Ports
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={ports}
            loading={isLoading}
            searchKey="name"
            searchPlaceholder="Search ports..."
            filterableColumns={[
              {
                id: 'status',
                title: 'Status',
                options: [
                  { label: 'Up', value: 'up' },
                  { label: 'Down', value: 'down' },
                  { label: 'Blocked', value: 'blocked' },
                ],
              },
            ]}
            bulkActions={[
              {
                label: 'Delete',
                onClick: handleBulkDelete,
                variant: 'destructive',
              },
            ]}
            pagination
            pageSize={10}
          />
        </CardContent>
      </Card>
    </div>
  );
}
