'use client';

import { useState } from 'react';
import { Loader2, Plus, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
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
import { useOverlay, useApi, useToast } from '@/hooks';
import type { NetworkOverlay } from '@/types/infrastructure';
import type { ListVNIsResponse, VNI } from 'trusted-platform-sdk';

export default function NetworkOverlaysPage() {
  const { toast } = useToast();
  const overlay = useOverlay();
  const [createOpen, setCreateOpen] = useState(false);
  const [createVni, setCreateVni] = useState('');
  const [createName, setCreateName] = useState('');
  const [createSubmitting, setCreateSubmitting] = useState(false);

  // SDK returns VNI objects, transform to NetworkOverlay format
  const {
    data: vniData,
    isLoading,
    refetch: fetchOverlays,
  } = useApi<ListVNIsResponse>(() => overlay.listVNIs(), []);

  // Transform VNI data to NetworkOverlay format for UI
  const overlays: NetworkOverlay[] = (vniData?.vnis || []).map((vni: VNI) => ({
    id: vni.id,
    name: vni.config.name || `VNI-${vni.config.vni}`,
    type: 'vxlan' as const,
    vni: vni.config.vni,
    status: 'active' as const, // TODO: Add status field to VNI type in SDK
    nodes: [], // TODO: Get nodes from listVTEPs or tunnel info
    createdAt: vni.createdAt,
  }));

  const stats = {
    total: overlays.length,
    active: overlays.filter((o) => o.status === 'active').length,
    pending: overlays.filter((o) => o.status === 'pending').length,
    totalNodes: overlays.reduce((sum, o) => sum + o.nodes.length, 0),
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Network Overlays</h1>
          <p className="text-muted-foreground mt-1">
            Manage VXLAN, GRE, and other overlay networks
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={fetchOverlays}
            disabled={isLoading}
          >
            <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
          </Button>
          <Button onClick={() => setCreateOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Create Overlay
          </Button>
        </div>
      </div>

      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Overlay (VXLAN VNI)</DialogTitle>
            <DialogDescription>
              Create a new VXLAN Network Identifier for tenant overlay traffic.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="vni-id">VNI *</Label>
              <Input
                id="vni-id"
                type="number"
                min={1}
                max={16777215}
                value={createVni}
                onChange={(e) => setCreateVni(e.target.value)}
                placeholder="10000"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="vni-name">Name (optional)</Label>
              <Input
                id="vni-name"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="tenant-default"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCreateOpen(false)}>Cancel</Button>
            <Button
              disabled={!createVni || createSubmitting}
              onClick={async () => {
                const v = Number.parseInt(createVni, 10);
                if (!Number.isFinite(v) || v < 1) {
                  toast({ title: 'Invalid VNI', variant: 'destructive' });
                  return;
                }
                setCreateSubmitting(true);
                try {
                  await overlay.createVNI({ config: { vni: v, name: createName || undefined } });
                  toast({ title: 'Overlay created', variant: 'success' });
                  setCreateOpen(false);
                  setCreateVni('');
                  setCreateName('');
                  fetchOverlays();
                } catch (err) {
                  toast({
                    title: 'Failed to create overlay',
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
          <div className="text-sm font-medium text-muted-foreground">Total Overlays</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Active</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.active}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Pending</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">
            {stats.pending}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total Nodes</div>
          <div className="text-3xl font-bold mt-2">{stats.totalNodes}</div>
        </div>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      ) : (
        <div className="rounded-md border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>VNI</TableHead>
                <TableHead>Nodes</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {overlays.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="text-center text-muted-foreground"
                  >
                    No network overlays found
                  </TableCell>
                </TableRow>
              ) : (
                overlays.map((overlay) => (
                  <TableRow key={overlay.id}>
                    <TableCell className="font-medium">{overlay.name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="uppercase">
                        {overlay.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono">
                      {overlay.vni ?? '-'}
                    </TableCell>
                    <TableCell>
                      <div className="space-y-1">
                        <div className="font-medium">
                          {overlay.nodes.length} nodes
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {overlay.nodes.filter((n) => n.status === 'connected').length}{' '}
                          connected
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          overlay.status === 'active'
                            ? 'bg-green-500/10 text-green-500 border-green-500/20'
                            : overlay.status === 'pending'
                              ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20'
                              : 'bg-red-500/10 text-red-500 border-red-500/20'
                        }
                      >
                        {overlay.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="sm">
                        Manage
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
