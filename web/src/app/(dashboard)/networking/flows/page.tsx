'use client';

import { useState, useMemo, useCallback } from 'react';
import { Plus, RefreshCw, ArrowRightLeft, Play, Pause, Trash2, AlertCircle, Loader2 } from 'lucide-react';
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
import type { Flow, FlowMatch, FlowAction } from 'trusted-platform-sdk';
import { flowActionKind, flowTableNumber, readUint64 } from '@/lib/sdn-wire';

// Types for OpenFlow flow management
interface OpenFlowRule {
  id: string;
  name: string;
  switch: string;
  table: number;
  priority: number;
  match: FlowMatch;
  actions: FlowAction[];
  status: 'active' | 'inactive' | 'error';
  packets: number;
  bytes: number;
  duration: number;
  idleTimeout: number;
  hardTimeout: number;
  cookie: string;
  createdAt: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatDuration(seconds: number): string {
  if (seconds === 0) return '-';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  return `${minutes}m`;
}

function formatMatchConditions(match: FlowMatch | undefined | null): string {
  if (!match) return '*';
  const conditions: string[] = [];
  if (match.inPort) conditions.push(`in_port=${match.inPort}`);
  if (match.ethSrc) conditions.push(`eth_src=${match.ethSrc}`);
  if (match.ethDst) conditions.push(`eth_dst=${match.ethDst}`);
  if (match.ethType) conditions.push(`eth_type=${match.ethType}`);
  if (match.vlanId) conditions.push(`vlan_id=${match.vlanId}`);
  if (match.ipSrc) conditions.push(`ip_src=${match.ipSrc}`);
  if (match.ipDst) conditions.push(`ip_dst=${match.ipDst}`);
  if (match.ipProto) conditions.push(`ip_proto=${match.ipProto}`);
  if (match.tcpSrc) conditions.push(`tcp_src=${match.tcpSrc}`);
  if (match.tcpDst) conditions.push(`tcp_dst=${match.tcpDst}`);
  if (match.udpSrc) conditions.push(`udp_src=${match.udpSrc}`);
  if (match.udpDst) conditions.push(`udp_dst=${match.udpDst}`);
  return conditions.join(', ') || '*';
}

function formatActions(actions: FlowAction[] | undefined | null): string {
  if (!actions || !Array.isArray(actions)) return '-';
  return actions.map((a) => {
    const kind = flowActionKind(a.type);
    if (a.port !== undefined) {
      return `${kind}(${a.port})`;
    }
    if (a.vlanId !== undefined) {
      return `${kind}(vlan:${a.vlanId})`;
    }
    if (a.tableId !== undefined) {
      return `${kind}(table:${a.tableId})`;
    }
    if (a.field !== undefined && a.value !== undefined) {
      return `${kind}(${a.field}=${a.value})`;
    }
    return kind;
  }).join(', ');
}

export default function OpenFlowsPage() {
  const { toast } = useToast();
  const sdn = useSDN();
  const [selectedBridgeId, setSelectedBridgeId] = useState<string>('');
  const [createOpen, setCreateOpen] = useState(false);
  const [createPriority, setCreatePriority] = useState('100');
  const [createInPort, setCreateInPort] = useState('');
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

  // Fetch flows for the selected bridge
  const {
    data: flowsData,
    isLoading: flowsLoading,
    error: flowsError,
    refetch: refetchFlows,
  } = useApi(
    () => selectedBridgeId ? sdn.listFlows({ bridgeId: selectedBridgeId }) : Promise.resolve({ success: true, data: { flows: [] } }),
    [selectedBridgeId],
    {
      onError: (err) => {
        toast({
          title: 'Error loading flows',
          description: err.message,
          variant: 'destructive',
        });
      },
    }
  );

  // Transform SDK flows to UI format
  const flows = useMemo<OpenFlowRule[]>(() => {
    if (!flowsData?.flows) return [];
    return flowsData.flows.map((flow: Flow) => ({
      id: flow.id,
      name: flow.config?.metadata?.['name'] || flow.id,
      switch: selectedBridgeId,
      table: flowTableNumber(flow.config?.table),
      priority: flow.config?.priority || 0,
      match: flow.config?.match || {} as FlowMatch,
      actions: flow.config?.actions || [],
      status: 'active' as const,
      packets: readUint64(flow.stats?.packetCount),
      bytes: readUint64(flow.stats?.byteCount),
      duration: flow.stats?.durationSeconds || 0,
      idleTimeout: flow.config?.idleTimeout || 0,
      hardTimeout: flow.config?.hardTimeout || 0,
      cookie: flow.config?.metadata?.['cookie'] || '',
      createdAt: flow.createdAt || new Date().toISOString(),
    }));
  }, [flowsData, selectedBridgeId]);

  const isLoading = bridgesLoading || flowsLoading;
  const error = bridgesError || flowsError;

  const fetchFlows = useCallback(() => {
    refetchBridges();
    if (selectedBridgeId) {
      refetchFlows();
    }
  }, [refetchBridges, refetchFlows, selectedBridgeId]);

  const handleViewFlow = (flow: OpenFlowRule) => {
    toast({
      title: 'View Flow',
      description: `Viewing details for flow "${flow.name}"`,
    });
  };

  const handleEditFlow = (flow: OpenFlowRule) => {
    toast({
      title: 'Edit Flow',
      description: `Editing flow "${flow.name}"`,
    });
  };

  const handleToggleFlow = (flow: OpenFlowRule) => {
    toast({
      title: 'Toggle Flow',
      description: `Toggling flow "${flow.name}" is not yet implemented`,
    });
  };

  const handleDuplicateFlow = (flow: OpenFlowRule) => {
    toast({
      title: 'Duplicate Flow',
      description: `Duplicating flow "${flow.name}" is not yet implemented`,
    });
  };

  const handleDeleteFlow = async (flow: OpenFlowRule) => {
    if (!selectedBridgeId) return;
    try {
      await sdn.deleteFlow(selectedBridgeId, flow.id);
      toast({
        title: 'Flow Deleted',
        description: `Flow "${flow.name}" has been deleted`,
      });
      refetchFlows();
    } catch (err) {
      toast({
        title: 'Error deleting flow',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const columns: ColumnDef<OpenFlowRule>[] = [
    createSelectColumn<OpenFlowRule>(),
    {
      accessorKey: 'name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Name" />
      ),
      cell: ({ row }) => (
        <div className="flex flex-col">
          <span className="font-medium">{row.getValue('name')}</span>
          <span className="text-xs text-muted-foreground">{row.original.cookie}</span>
        </div>
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
      accessorKey: 'table',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Table" />
      ),
      cell: ({ row }) => (
        <span className="font-mono">T{row.getValue('table')}</span>
      ),
    },
    {
      accessorKey: 'priority',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Priority" />
      ),
      cell: ({ row }) => (
        <Badge variant="secondary">{row.getValue('priority')}</Badge>
      ),
    },
    {
      accessorKey: 'match',
      header: 'Match',
      cell: ({ row }) => (
        <span className="font-mono text-xs max-w-[200px] truncate block" title={formatMatchConditions(row.getValue('match'))}>
          {formatMatchConditions(row.getValue('match'))}
        </span>
      ),
    },
    {
      accessorKey: 'actions',
      header: 'Actions',
      cell: ({ row }) => (
        <span className="font-mono text-xs max-w-[150px] truncate block" title={formatActions(row.getValue('actions'))}>
          {formatActions(row.getValue('actions'))}
        </span>
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
            icon: Play,
            className: 'bg-green-500/10 text-green-500 border-green-500/20',
          },
          inactive: {
            icon: Pause,
            className: 'bg-gray-500/10 text-gray-500 border-gray-500/20',
          },
          error: {
            icon: Trash2,
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
      accessorKey: 'packets',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Packets" />
      ),
      cell: ({ row }) => (
        <span className="font-mono text-sm">
          {(row.getValue('packets') as number).toLocaleString()}
        </span>
      ),
    },
    {
      accessorKey: 'bytes',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Bytes" />
      ),
      cell: ({ row }) => formatBytes(row.getValue('bytes')),
    },
    {
      accessorKey: 'duration',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="Duration" />
      ),
      cell: ({ row }) => formatDuration(row.getValue('duration')),
    },
    {
      id: 'actions',
      cell: ({ row }) => (
        <DataTableRowActions
          row={row.original}
          actions={[
            { label: 'View Details', onClick: handleViewFlow },
            { label: 'Edit', onClick: handleEditFlow },
            { label: 'Duplicate', onClick: handleDuplicateFlow },
            {
              label: row.original.status === 'active' ? 'Deactivate' : 'Activate',
              onClick: handleToggleFlow,
              separator: true,
            },
            {
              label: 'Delete',
              onClick: handleDeleteFlow,
              variant: 'destructive',
              separator: true,
            },
          ]}
        />
      ),
    },
  ];

  const stats = {
    total: flows.length,
    active: flows.filter((f) => f.status === 'active').length,
    inactive: flows.filter((f) => f.status === 'inactive').length,
    error: flows.filter((f) => f.status === 'error').length,
    totalPackets: flows.reduce((sum, f) => sum + f.packets, 0),
    totalBytes: flows.reduce((sum, f) => sum + f.bytes, 0),
  };

  const handleBulkDelete = async (selectedFlows: OpenFlowRule[]) => {
    if (!selectedBridgeId) return;
    try {
      await Promise.all(
        selectedFlows.map((f) => sdn.deleteFlow(selectedBridgeId, f.id))
      );
      toast({
        title: 'Flows Deleted',
        description: `${selectedFlows.length} flow rules have been deleted`,
      });
      refetchFlows();
    } catch (err) {
      toast({
        title: 'Error deleting flows',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const handleBulkDeactivate = (selectedFlows: OpenFlowRule[]) => {
    toast({
      title: 'Bulk Deactivate',
      description: `Deactivating ${selectedFlows.length} flows is not yet implemented`,
    });
  };

  // Show error state
  if (error) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Flows</AlertTitle>
          <AlertDescription>
            {error.message}
            <Button
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchFlows}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  // Show loading state
  if (isLoading && flows.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading flows...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">OpenFlow Rules</h1>
          <p className="text-muted-foreground mt-1">
            Manage OpenFlow flow rules and traffic forwarding policies
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchFlows} disabled={isLoading}>
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)} disabled={!selectedBridgeId}>
            <Plus className="mr-2 h-4 w-4" />
            Add Flow Rule
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Flow Rule</DialogTitle>
            <DialogDescription>
              Add a basic flow that forwards traffic on bridge {selectedBridgeId || 'unknown'}.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="flow-priority">Priority</Label>
              <Input
                id="flow-priority"
                type="number"
                min={0}
                value={createPriority}
                onChange={(e) => setCreatePriority(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="flow-inport">Match: In-Port (optional)</Label>
              <Input
                id="flow-inport"
                value={createInPort}
                onChange={(e) => setCreateInPort(e.target.value)}
                placeholder="1"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={createSubmitting || !selectedBridgeId}
              onClick={async () => {
                setCreateSubmitting(true);
                try {
                  const match: FlowMatch = {};
                  if (createInPort) match.inPort = createInPort;
                  await sdn.addFlow({
                    config: {
                      bridgeId: selectedBridgeId,
                      priority: Number.parseInt(createPriority, 10) || 100,
                      match,
                      // An output action with no port is NORMAL forwarding.
                      actions: [{ type: 'FLOW_ACTION_OUTPUT' }],
                    },
                  });
                  toast({ title: 'Flow rule added', variant: 'success' });
                  setCreateOpen(false);
                  setCreateInPort('');
                  refetchFlows();
                } catch (err) {
                  toast({
                    title: 'Failed to add flow',
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

      <div className="grid gap-4 md:grid-cols-6">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Rules</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Active</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.active}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Inactive</div>
          <div className="text-3xl font-bold mt-2 text-gray-500">{stats.inactive}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Errors</div>
          <div className="text-3xl font-bold mt-2 text-red-500">{stats.error}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Packets</div>
          <div className="text-3xl font-bold mt-2">{(stats.totalPackets / 1000000).toFixed(1)}M</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Traffic</div>
          <div className="text-3xl font-bold mt-2">{formatBytes(stats.totalBytes)}</div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ArrowRightLeft className="h-5 w-5" />
            Flow Rules
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={flows}
            loading={isLoading}
            searchKey="name"
            searchPlaceholder="Search flow rules..."
            filterableColumns={[
              {
                id: 'status',
                title: 'Status',
                options: [
                  { label: 'Active', value: 'active' },
                  { label: 'Inactive', value: 'inactive' },
                  { label: 'Error', value: 'error' },
                ],
              },
            ]}
            bulkActions={[
              {
                label: 'Deactivate',
                onClick: handleBulkDeactivate,
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
