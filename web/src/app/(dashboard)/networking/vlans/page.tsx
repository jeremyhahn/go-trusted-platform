'use client';

import { useState, useMemo, useCallback } from 'react';
import { Plus, RefreshCw, Layers, Network, Server, AlertTriangle, AlertCircle, Loader2 } from 'lucide-react';
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
import { useToast } from '@/hooks/use-toast';
import { useSDN, useApi } from '@/hooks';
import type { VLAN } from 'trusted-platform-sdk';

// Types for VLAN management
interface VLANDisplay {
  id: string;
  vlanId: number;
  name: string;
  description?: string;
  status: 'active' | 'suspended' | 'error';
  ipRange?: string;
  gateway?: string;
  subnet?: string;
  portCount: number;
  mtu: number;
  layer: 2 | 3;
  routingEnabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export default function VLANsPage() {
  const { toast } = useToast();
  const sdn = useSDN();
  const [selectedBridgeId, setSelectedBridgeId] = useState<string>('');
  const [createOpen, setCreateOpen] = useState(false);
  const [createVlanId, setCreateVlanId] = useState('');
  const [createName, setCreateName] = useState('');
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

  // Fetch VLANs for the selected bridge
  const {
    data: vlansData,
    isLoading: vlansLoading,
    error: vlansError,
    refetch: refetchVlans,
  } = useApi(
    () => selectedBridgeId ? sdn.listVLANs({ bridgeId: selectedBridgeId }) : Promise.resolve({ success: true, data: { vlans: [] } }),
    [selectedBridgeId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading VLANs',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK VLANs to UI format
  const vlans = useMemo<VLANDisplay[]>(() => {
    if (!vlansData?.vlans) return [];
    return vlansData.vlans.map((vlan: VLAN) => ({
      id: vlan.id,
      vlanId: vlan.config?.vlanId ?? 0,
      name: vlan.config?.name || `VLAN ${vlan.config?.vlanId ?? vlan.id}`,
      description: undefined,
      status: 'active' as const,
      ipRange: undefined,
      gateway: undefined,
      subnet: undefined,
      portCount: vlan.config?.ports?.length ?? vlan.stats?.portCount ?? 0,
      mtu: 1500,
      layer: 2,
      routingEnabled: false,
      createdAt: vlan.createdAt || new Date().toISOString(),
      updatedAt: vlan.createdAt || new Date().toISOString(),
    }));
  }, [vlansData]);

  const isLoading = bridgesLoading || vlansLoading;
  const error = bridgesError || vlansError;

  const fetchVlans = useCallback(() => {
    refetchBridges();
    if (selectedBridgeId) {
      refetchVlans();
    }
  }, [refetchBridges, refetchVlans, selectedBridgeId]);

  const handleViewVlan = (vlan: VLANDisplay) => {
    toast({
      title: 'View VLAN',
      description: `Viewing details for VLAN ${vlan.vlanId} (${vlan.name})`,
    });
  };

  const handleEditVlan = (vlan: VLANDisplay) => {
    toast({
      title: 'Edit VLAN',
      description: `Editing VLAN ${vlan.vlanId} (${vlan.name})`,
    });
  };

  const handleToggleVlan = (vlan: VLANDisplay) => {
    toast({
      title: 'Toggle VLAN',
      description: `Toggling VLAN ${vlan.vlanId} is not yet implemented`,
    });
  };

  const handleManagePorts = (vlan: VLANDisplay) => {
    toast({
      title: 'Manage Ports',
      description: `Managing ports for VLAN ${vlan.vlanId} (${vlan.name})`,
    });
  };

  const handleDeleteVlan = async (vlan: VLANDisplay) => {
    if (!selectedBridgeId) return;
    if (vlan.vlanId === 1) {
      toast({
        title: 'Cannot Delete',
        description: 'Default VLAN cannot be deleted',
        variant: 'destructive',
      });
      return;
    }
    try {
      await sdn.deleteVLAN(selectedBridgeId, vlan.vlanId);
      toast({
        title: 'VLAN Deleted',
        description: `VLAN ${vlan.vlanId} (${vlan.name}) has been deleted`,
      });
      refetchVlans();
    } catch (err) {
      toast({
        title: 'Error deleting VLAN',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const columns: ColumnDef<VLANDisplay>[] = [
    createSelectColumn<VLANDisplay>(),
    {
      accessorKey: 'vlanId',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="VLAN ID" />
      ),
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <Layers className="h-4 w-4 text-muted-foreground" />
          <span className="font-mono font-bold">{row.getValue('vlanId')}</span>
        </div>
      ),
    },
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.getValue('name')}</span>
          {row.original.description && (
            <span className="text-xs text-muted-foreground truncate max-w-[200px]">
              {row.original.description}
            </span>
          )}
        </div>
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
          active: {
            icon: Network,
            className: 'bg-green-500/10 text-green-500 border-green-500/20',
          },
          suspended: {
            icon: Server,
            className: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20',
          },
          error: {
            icon: AlertTriangle,
            className: 'bg-red-500/10 text-red-500 border-red-500/20',
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
      accessorKey: 'ipRange',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="IP Range" />
      ),
      cell: ({ row }) => {
        const ipRange = row.getValue('ipRange') as string | undefined;
        return ipRange ? (
          <span className="font-mono text-sm">{ipRange}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        );
      },
    },
    {
      accessorKey: 'gateway',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Gateway" />
      ),
      cell: ({ row }) => {
        const gateway = row.getValue('gateway') as string | undefined;
        return gateway ? (
          <span className="font-mono text-sm">{gateway}</span>
        ) : (
          <span className="text-muted-foreground">-</span>
        );
      },
    },
    {
      accessorKey: 'layer',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Layer" />
      ),
      cell: ({ row }) => (
        <Badge variant="secondary">L{row.getValue('layer')}</Badge>
      ),
    },
    {
      accessorKey: 'mtu',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="MTU" />
      ),
      cell: ({ row }) => {
        const mtu = row.getValue('mtu') as number;
        const isJumbo = mtu > 1500;
        return (
          <span className={`font-mono text-sm ${isJumbo ? 'text-blue-500' : ''}`}>
            {mtu}
            {isJumbo && <span className="text-xs ml-1">(jumbo)</span>}
          </span>
        );
      },
    },
    {
      accessorKey: 'portCount',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Ports" />
      ),
      cell: ({ row }) => {
        const count = row.getValue('portCount') as number;
        return (
          <Badge variant={count > 0 ? 'default' : 'secondary'}>
            {count} port{count !== 1 ? 's' : ''}
          </Badge>
        );
      },
    },
    {
      accessorKey: 'routingEnabled',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Routing" />
      ),
      cell: ({ row }) => {
        const enabled = row.getValue('routingEnabled') as boolean;
        return (
          <Badge
            variant="outline"
            className={enabled
              ? 'bg-blue-500/10 text-blue-500 border-blue-500/20'
              : 'bg-gray-500/10 text-gray-500 border-gray-500/20'
            }
          >
            {enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        );
      },
    },
    {
      id: 'actions',
      cell: ({ row }) => (
        <DataTableRowActions
          row={row.original}
          actions={[
            { label: 'View Details', onClick: handleViewVlan },
            { label: 'Edit', onClick: handleEditVlan },
            { label: 'Manage Ports', onClick: handleManagePorts },
            {
              label: row.original.status === 'active' ? 'Suspend' : 'Activate',
              onClick: handleToggleVlan,
              separator: true,
            },
            {
              label: 'Delete',
              onClick: handleDeleteVlan,
              variant: 'destructive',
              separator: true,
            },
          ]}
        />
      ),
    },
  ];

  const stats = {
    total: vlans.length,
    active: vlans.filter((v) => v.status === 'active').length,
    suspended: vlans.filter((v) => v.status === 'suspended').length,
    error: vlans.filter((v) => v.status === 'error').length,
    layer2: vlans.filter((v) => v.layer === 2).length,
    layer3: vlans.filter((v) => v.layer === 3).length,
    totalPorts: vlans.reduce((sum, v) => sum + v.portCount, 0),
  };

  const handleBulkDelete = async (selectedVlans: VLANDisplay[]) => {
    if (!selectedBridgeId) return;
    const deletable = selectedVlans.filter((v) => v.vlanId !== 1);
    if (deletable.length < selectedVlans.length) {
      toast({
        title: 'Partial Delete',
        description: 'Default VLAN was excluded from deletion',
      });
    }
    if (deletable.length === 0) return;

    try {
      await Promise.all(
        deletable.map((v) => sdn.deleteVLAN(selectedBridgeId, v.vlanId))
      );
      toast({
        title: 'VLANs Deleted',
        description: `${deletable.length} VLANs have been deleted`,
      });
      refetchVlans();
    } catch (err) {
      toast({
        title: 'Error deleting VLANs',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleBulkSuspend = (selectedVlans: VLANDisplay[]) => {
    toast({
      title: 'Bulk Suspend',
      description: `Suspending ${selectedVlans.length} VLANs is not yet implemented`,
    });
  };

  // Show error state
  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading VLANs</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchVlans}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Show loading state
  if (isLoading && vlans.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading VLANs...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">VLAN Management</h1>
          <p className="text-muted-foreground mt-1">
            Configure and manage Virtual LANs for network segmentation
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchVlans} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)} disabled={!selectedBridgeId}>
            <Plus className="mr-2 h-4 w-4" />
            Create VLAN
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create VLAN</DialogTitle>
            <DialogDescription>
              Add a VLAN to bridge {selectedBridgeId || 'unknown'}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="vlan-id">VLAN ID *</Label>
              <Input
                id="vlan-id"
                type="number"
                min={1}
                max={4095}
                value={createVlanId}
                onChange={(e) => setCreateVlanId(e.target.value)}
                placeholder="100"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vlan-name">Name (optional)</Label>
              <Input
                id="vlan-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="prod-data"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!createVlanId || createSubmitting || !selectedBridgeId}
              onClick={async () => {
                const vid = Number.parseInt(createVlanId, 10);
                if (!Number.isFinite(vid) || vid < 1 || vid > 4095) {
                  toast({ title: 'Invalid VLAN ID', description: 'Must be 1-4095', variant: 'destructive' });
                  return;
                }
                setCreateSubmitting(true);
                try {
                  await sdn.createVLAN({
                    config: { vlanId: vid, name: createName || undefined, bridgeId: selectedBridgeId },
                  });
                  toast({ title: 'VLAN created', variant: 'success' });
                  setCreateOpen(false);
                  setCreateVlanId('');
                  setCreateName('');
                  refetchVlans();
                } catch (err) {
                  toast({
                    title: 'Failed to create VLAN',
                    description: err instanceof Error ? err.message : 'Unknown error',
                    variant: 'destructive',
                  });
                } finally {
                  setCreateSubmitting(false);
                }
              }}
            >
              {createSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Create
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className="grid gap-4 md:grid-cols-7">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total VLANs</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Active</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.active}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Suspended</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">{stats.suspended}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Errors</div>
          <div className="text-3xl font-bold mt-2 text-red-500">{stats.error}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Layer 2</div>
          <div className="text-3xl font-bold mt-2">{stats.layer2}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Layer 3</div>
          <div className="text-3xl font-bold mt-2 text-blue-500">{stats.layer3}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Ports</div>
          <div className="text-3xl font-bold mt-2">{stats.totalPorts}</div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Layers className="h-5 w-5" />
            Virtual LANs
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={vlans}
            loading={isLoading}
            searchKey="name"
            searchPlaceholder="Search VLANs..."
            filterableColumns={[
              {
                id: 'status',
                title: 'Status',
                options: [
                  { label: 'Active', value: 'active' },
                  { label: 'Suspended', value: 'suspended' },
                  { label: 'Error', value: 'error' },
                ],
              },
            ]}
            bulkActions={[
              {
                label: 'Suspend',
                onClick: handleBulkSuspend,
                variant: 'default',
              },
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
