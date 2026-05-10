'use client';

/**
 * Software-Defined Networking Page
 *
 * Displays virtual networks, topology, and flow rules.
 * Uses the trusted-platform-sdk for API interactions.
 */

import { useMemo, useState } from 'react';
import { Loader2, Plus, RefreshCw, Network as NetworkIcon } from 'lucide-react';
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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { SDNTopology } from '@/components/features/networking/sdn-topology';
import { useSDN, useApi, useToast } from '@/hooks';
import type { Network, FlowRule, FlowAction } from '@/types/infrastructure';

export default function SDNPage() {
  const { toast } = useToast();
  const sdn = useSDN();
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createType, setCreateType] = useState<'ovs' | 'linux'>('ovs');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // Fetch bridges using SDK
  const {
    data: bridgesData,
    isLoading: bridgesLoading,
    refetch: refetchBridges,
  } = useApi(
    () => sdn.listBridges(),
    [],
    {
      onError: (err) => {
        toast({
          title: 'Error',
          description: `Failed to fetch bridges: ${err.message}`,
          variant: 'destructive',
        });
      },
    }
  );

  // Get first bridge ID for fetching flows (if available)
  const firstBridgeId = bridgesData?.bridges?.[0]?.id;

  // Fetch flows for first bridge using SDK
  const {
    data: flowsData,
    isLoading: flowsLoading,
  } = useApi(
    () => firstBridgeId ? sdn.listFlows({ bridgeId: firstBridgeId }) : Promise.resolve({ success: true, data: null }),
    [firstBridgeId],
    {
      onError: (err) => {
        console.warn('Failed to fetch flows:', err.message);
      },
    }
  );

  const loading = bridgesLoading || flowsLoading;

  const fetchData = () => {
    refetchBridges();
  };

  // Transform SDK bridges to local Network type for UI compatibility.
  // The server returns flat bridge records (id/name/type/status/created_at)
  // rather than the SDK's nested {config: BridgeConfig} shape. Read both
  // shapes so the page works regardless of which contract is on the wire.
  const networks: Network[] = useMemo(() => {
    if (!bridgesData?.bridges) return [];
    return bridgesData.bridges.map((bridge: any) => {
      const name = bridge.config?.name || bridge.name || bridge.id;
      const rawType = bridge.config?.type || bridge.type || '';
      return {
        id: bridge.id,
        name,
        type: (String(rawType).toLowerCase() === 'ovs' ? 'overlay' : 'vlan') as Network['type'],
        cidr: '',
        gateway: undefined,
        status: 'active' as Network['status'],
        vlanId: undefined,
        createdAt:
          bridge.createdAt ||
          bridge.created_at ||
          new Date().toISOString(),
      };
    });
  }, [bridgesData]);

  // Build topology from bridges (simplified view - bridges as nodes)
  const topology = useMemo(() => {
    if (!bridgesData?.bridges) {
      return { nodes: [], links: [] };
    }
    return {
      nodes: bridgesData.bridges.map((bridge) => ({
        id: bridge.id,
        name: bridge.config?.name || bridge.id,
        type: 'switch' as 'switch' | 'router' | 'host',
      })),
      links: [] as { source: string; target: string; bandwidth?: number }[],
    };
  }, [bridgesData]);

  // Transform SDK flows to local FlowRule type
  const flowRules: FlowRule[] = useMemo(() => {
    if (!flowsData?.flows) return [];
    return flowsData.flows.map((flow) => {
      const sdkMatch = flow.config?.match;
      return {
        id: flow.id,
        switchId: flow.config?.bridgeId || '',
        table: typeof flow.config?.table === 'number' ? flow.config.table : 0,
        priority: flow.config?.priority || 0,
        match: sdkMatch ? {
          inPort: sdkMatch.inPort,
          ethSrc: sdkMatch.ethSrc,
          ethDst: sdkMatch.ethDst,
          ethType: sdkMatch.ethType !== undefined ? String(sdkMatch.ethType) : undefined,
          vlanId: sdkMatch.vlanId,
          ipSrc: sdkMatch.ipSrc,
          ipDst: sdkMatch.ipDst,
          ipProto: sdkMatch.ipProto !== undefined ? String(sdkMatch.ipProto) : undefined,
          tcpSrc: sdkMatch.tcpSrc,
          tcpDst: sdkMatch.tcpDst,
          udpSrc: sdkMatch.udpSrc,
          udpDst: sdkMatch.udpDst,
        } : {},
        actions: (flow.config?.actions || []).map((a: { type?: string; port?: string }) => ({
          type: (a.type || 'output') as FlowAction['type'],
          value: a.port,
        })),
        packets: flow.stats?.packetCount || 0,
        bytes: flow.stats?.byteCount || 0,
        duration: flow.stats?.durationSeconds || 0,
      };
    });
  }, [flowsData]);

  const stats = {
    networks: networks.length,
    active: networks.filter((n) => n.status === 'active').length,
    flows: flowRules.length,
    nodes: topology.nodes.length,
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Software-Defined Networking</h1>
          <p className="text-muted-foreground mt-1">
            Manage virtual networks and flow rules
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="icon" onClick={fetchData} disabled={loading}>
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Network
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Network (Bridge)</DialogTitle>
            <DialogDescription>
              Create an SDN bridge that flows, ports, and VLANs can attach to.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="bridge-name">Name *</Label>
              <Input
                id="bridge-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="br-prod"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="bridge-type">Type</Label>
              <Select value={createType} onValueChange={(v) => setCreateType(v as 'ovs' | 'linux')}>
                <SelectTrigger id="bridge-type"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="ovs">OVS (Open vSwitch)</SelectItem>
                  <SelectItem value="linux">Linux Bridge</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!createName || createSubmitting}
              onClick={async () => {
                setCreateSubmitting(true);
                try {
                  // The platform SDN REST handler expects a flat
                  // {name, type} body, not the SDK's nested
                  // {config: {...}} shape; bypass the SDK typing.
                  await sdn.createBridge({
                    name: createName,
                    type: createType === 'ovs' ? 'BRIDGE_TYPE_OVS' : 'BRIDGE_TYPE_LINUX',
                  } as any);
                  toast({ title: 'Network created', variant: 'success' });
                  setCreateOpen(false);
                  setCreateName('');
                  refetchBridges();
                } catch (err) {
                  toast({
                    title: 'Failed to create network',
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

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Networks</div>
          <div className="text-3xl font-bold mt-2">{stats.networks}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Active</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.active}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Flow Rules</div>
          <div className="text-3xl font-bold mt-2">{stats.flows}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Nodes</div>
          <div className="text-3xl font-bold mt-2">{stats.nodes}</div>
        </div>
      </div>

      <SDNTopology nodes={topology.nodes} links={topology.links} />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <NetworkIcon className="h-5 w-5" />
            Virtual Networks
          </CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>CIDR</TableHead>
                  <TableHead>Gateway</TableHead>
                  <TableHead>Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {networks.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="text-center text-muted-foreground"
                    >
                      No networks found
                    </TableCell>
                  </TableRow>
                ) : (
                  networks.map((network) => (
                    <TableRow key={network.id}>
                      <TableCell className="font-medium">{network.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="capitalize">
                          {network.type}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {network.cidr}
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {network.gateway || '-'}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={
                            network.status === 'active'
                              ? 'bg-green-500/10 text-green-500 border-green-500/20'
                              : 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                          }
                        >
                          {network.status}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Flow Rules</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center h-32">
              <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Priority</TableHead>
                  <TableHead>Table</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead>Actions</TableHead>
                  <TableHead>Packets</TableHead>
                  <TableHead>Bytes</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {flowRules.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={6}
                      className="text-center text-muted-foreground"
                    >
                      No flow rules found
                    </TableCell>
                  </TableRow>
                ) : (
                  flowRules.slice(0, 10).map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell className="font-medium">{rule.priority}</TableCell>
                      <TableCell>{rule.table}</TableCell>
                      <TableCell className="font-mono text-xs max-w-xs truncate">
                        {JSON.stringify(rule.match)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {rule.actions.map((a) => a.type).join(', ')}
                      </TableCell>
                      <TableCell>{rule.packets.toLocaleString()}</TableCell>
                      <TableCell>{(rule.bytes / 1024).toFixed(1)} KB</TableCell>
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
