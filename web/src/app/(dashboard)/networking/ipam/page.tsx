'use client';

import * as React from 'react';
import { Plus, RefreshCw, Database, AlertCircle, Loader2, Filter } from 'lucide-react';
import { ColumnDef } from '@tanstack/react-table';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { useToast } from '@/hooks/use-toast';

// uint64 arrives as JSON string — render as-is, never parseInt
type Uint64String = string;

interface IPAMPoolResponse {
  id: string;
  name: string;
  cidr: string;
  gateway: string;
  zone: string;
  description: string;
  total: Uint64String;
  allocated: Uint64String;
  available: Uint64String;
  default_lease_duration_nanos: number;
  inactivity_timeout_nanos: number;
  created_at: string;
  updated_at: string;
}

interface IPAllocationResponse {
  ip: string;
  pool_id: string;
  device_id: string;
  hostname: string;
  allocated_at: string;
  expires_at: string;
}

interface PoolFormState {
  id: string;
  name: string;
  cidr: string;
  gateway: string;
  zone: string;
  description: string;
}

function emptyPoolForm(): PoolFormState {
  return { id: '', name: '', cidr: '', gateway: '', zone: '', description: '' };
}

function utilization(pool: IPAMPoolResponse): number {
  const total = Number(pool.total);
  const allocated = Number(pool.allocated);
  if (!total) return 0;
  return Math.round((allocated / total) * 100);
}

export default function IPAMPage() {
  const { toast } = useToast();

  const [pools, setPools] = React.useState<IPAMPoolResponse[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  const [zoneFilter, setZoneFilter] = React.useState('');
  const [zoneOptions, setZoneOptions] = React.useState<string[]>([]);

  const [formOpen, setFormOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<IPAMPoolResponse | null>(null);
  const [form, setForm] = React.useState<PoolFormState>(emptyPoolForm());
  const [submitting, setSubmitting] = React.useState(false);

  const [deleteTarget, setDeleteTarget] = React.useState<IPAMPoolResponse | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  // Allocations panel for selected pool
  const [allocationsPool, setAllocationsPool] = React.useState<IPAMPoolResponse | null>(null);
  const [allocations, setAllocations] = React.useState<IPAllocationResponse[]>([]);
  const [allocationsLoading, setAllocationsLoading] = React.useState(false);
  const [allocationsOpen, setAllocationsOpen] = React.useState(false);

  const fetchPools = React.useCallback(async (zone?: string) => {
    setLoading(true);
    setLoadError(null);
    try {
      const params = zone ? `?zone=${encodeURIComponent(zone)}` : '';
      const res = await fetch(`/api/v1/sdn/gateway/ipam/pools${params}`, {
        credentials: 'include',
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const body = await res.json();
      // The webservice wraps payloads in {payload}; the daemon REST
      // stack returns the body bare — accept both.
      const list: IPAMPoolResponse[] = body.payload?.pools ?? body.pools ?? [];
      setPools(list);
      // Collect unique zone values for the filter dropdown
      const seenZones = Array.from(new Set(list.map((p) => p.zone).filter(Boolean)));
      setZoneOptions(seenZones);
    } catch (err) {
      setLoadError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void fetchPools(zoneFilter || undefined);
  }, [fetchPools, zoneFilter]);

  const fetchAllocations = React.useCallback(async (pool: IPAMPoolResponse) => {
    setAllocationsPool(pool);
    setAllocationsLoading(true);
    setAllocationsOpen(true);
    try {
      const res = await fetch(
        `/api/v1/sdn/gateway/ipam/allocations?pool_id=${encodeURIComponent(pool.id)}`,
        { credentials: 'include' }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      const body = await res.json();
      setAllocations(body.payload?.allocations ?? body.allocations ?? []);
    } catch (err) {
      toast({
        title: 'Failed to load allocations',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
      setAllocations([]);
    } finally {
      setAllocationsLoading(false);
    }
  }, [toast]);

  const openCreate = React.useCallback(() => {
    setEditTarget(null);
    setForm(emptyPoolForm());
    setFormOpen(true);
  }, []);

  const openEdit = React.useCallback((pool: IPAMPoolResponse) => {
    setEditTarget(pool);
    setForm({
      id: pool.id,
      name: pool.name,
      cidr: pool.cidr, // shown disabled — immutable
      gateway: pool.gateway ?? '',
      zone: pool.zone ?? '',
      description: pool.description ?? '',
    });
    setFormOpen(true);
  }, []);

  const handleSubmit = React.useCallback(async () => {
    if (!editTarget && (!form.name.trim() || !form.cidr.trim())) return;
    setSubmitting(true);
    try {
      if (editTarget) {
        // CIDR is immutable — exclude it from update body
        const body = {
          name: form.name,
          gateway: form.gateway,
          zone: form.zone,
          description: form.description,
        };
        const res = await fetch(
          `/api/v1/sdn/gateway/ipam/pools/${encodeURIComponent(editTarget.id)}`,
          {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          }
        );
        if (!res.ok) {
          const b = await res.json().catch(() => ({}));
          throw new Error(b.error || `HTTP ${res.status}`);
        }
        toast({ title: 'Pool updated', variant: 'success' });
      } else {
        const body = {
          id: form.id || undefined,
          name: form.name,
          cidr: form.cidr,
          gateway: form.gateway || undefined,
          zone: form.zone || undefined,
          description: form.description || undefined,
        };
        const res = await fetch('/api/v1/sdn/gateway/ipam/pools', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (!res.ok) {
          const b = await res.json().catch(() => ({}));
          throw new Error(b.error || `HTTP ${res.status}`);
        }
        toast({ title: 'Pool created', variant: 'success' });
      }
      setFormOpen(false);
      void fetchPools(zoneFilter || undefined);
    } catch (err) {
      toast({
        title: editTarget ? 'Failed to update pool' : 'Failed to create pool',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  }, [form, editTarget, fetchPools, zoneFilter, toast]);

  const openDeleteConfirm = React.useCallback((pool: IPAMPoolResponse) => {
    setDeleteTarget(pool);
    setDeleteError(null);
    setDeleteConfirmOpen(true);
  }, []);

  const handleDelete = React.useCallback(async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const res = await fetch(
        `/api/v1/sdn/gateway/ipam/pools/${encodeURIComponent(deleteTarget.id)}`,
        { method: 'DELETE', credentials: 'include' }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `HTTP ${res.status}`);
      }
      toast({ title: 'Pool deleted', variant: 'success' });
      setDeleteConfirmOpen(false);
      setDeleteTarget(null);
      void fetchPools(zoneFilter || undefined);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, fetchPools, zoneFilter, toast]);

  const columns: ColumnDef<IPAMPoolResponse>[] = React.useMemo(
    () => [
      createSelectColumn<IPAMPoolResponse>(),
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
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
        accessorKey: 'cidr',
        header: ({ column }) => <DataTableColumnHeader column={column} title="CIDR" />,
        cell: ({ row }) => (
          <span className="font-mono text-sm">{row.getValue('cidr')}</span>
        ),
      },
      {
        accessorKey: 'zone',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Zone" />,
        cell: ({ row }) => {
          const zone = row.getValue('zone') as string;
          return zone ? (
            <Badge variant="outline" className="font-mono text-xs">{zone}</Badge>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
      },
      {
        id: 'utilization',
        header: 'Utilization',
        cell: ({ row }) => {
          const pool = row.original;
          const pct = utilization(pool);
          const colorClass =
            pct >= 90
              ? 'text-red-500'
              : pct >= 75
              ? 'text-yellow-500'
              : 'text-green-500';
          return (
            <div className="flex items-center gap-2 min-w-[120px]">
              <Progress value={pct} className="h-2 flex-1" />
              <span className={`text-xs font-mono ${colorClass}`}>{pct}%</span>
            </div>
          );
        },
      },
      {
        id: 'counts',
        header: 'Allocated / Total',
        cell: ({ row }) => {
          const pool = row.original;
          return (
            <span className="font-mono text-sm">
              {pool.allocated} / {pool.total}
            </span>
          );
        },
      },
      {
        id: 'available',
        header: 'Available',
        cell: ({ row }) => {
          const pool = row.original;
          return (
            <Badge
              variant="secondary"
              className={Number(pool.available) === 0 ? 'bg-red-500/10 text-red-500' : ''}
            >
              {pool.available}
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
              { label: 'Edit', onClick: openEdit },
              {
                label: 'View Allocations',
                onClick: fetchAllocations,
              },
              {
                label: 'Delete',
                onClick: openDeleteConfirm,
                variant: 'destructive',
                separator: true,
              },
            ]}
          />
        ),
      },
    ],
    [openEdit, openDeleteConfirm, fetchAllocations]
  );

  const stats = React.useMemo(() => ({
    total: pools.length,
    totalIPs: pools.reduce((s, p) => s + Number(p.total), 0),
    allocated: pools.reduce((s, p) => s + Number(p.allocated), 0),
    available: pools.reduce((s, p) => s + Number(p.available), 0),
  }), [pools]);

  if (loadError && pools.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading IPAM Pools</AlertTitle>
          <AlertDescription>
            {loadError}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={() => void fetchPools(zoneFilter || undefined)}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (loading && pools.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading IPAM pools...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">IPAM Pools</h1>
          <p className="text-muted-foreground mt-1">
            Manage IP address pools for network allocation
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={() => void fetchPools(zoneFilter || undefined)}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button type="button" onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Create Pool
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-4">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Pools</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total IPs</div>
          <div className="text-3xl font-bold mt-2">{stats.totalIPs.toLocaleString()}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Allocated</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">
            {stats.allocated.toLocaleString()}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Available</div>
          <div className="text-3xl font-bold mt-2 text-green-500">
            {stats.available.toLocaleString()}
          </div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5" />
              IP Address Pools
            </CardTitle>
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Select
                value={zoneFilter || '__all__'}
                onValueChange={(v) => setZoneFilter(v === '__all__' ? '' : v)}
              >
                <SelectTrigger className="w-40">
                  <SelectValue placeholder="All zones" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">All zones</SelectItem>
                  {zoneOptions.map((z) => (
                    <SelectItem key={z} value={z}>{z}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={pools}
            loading={loading}
            searchKey="name"
            searchPlaceholder="Search pools..."
            pagination
            pageSize={10}
          />
        </CardContent>
      </Card>

      {/* Create / Edit dialog */}
      <Dialog open={formOpen} onOpenChange={setFormOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>{editTarget ? `Edit Pool: ${editTarget.name}` : 'Create IPAM Pool'}</DialogTitle>
            <DialogDescription>
              {editTarget
                ? 'CIDR is immutable and cannot be changed after creation.'
                : 'Create a new IP address pool for network allocation.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="pool-name">Name *</Label>
              <Input
                id="pool-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="prod-pool"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-cidr">
                CIDR *
                {editTarget && (
                  <Badge variant="secondary" className="ml-2 text-xs">immutable</Badge>
                )}
              </Label>
              <Input
                id="pool-cidr"
                value={form.cidr}
                onChange={(e) => setForm((f) => ({ ...f, cidr: e.target.value }))}
                placeholder="10.0.0.0/24"
                disabled={!!editTarget}
                className={editTarget ? 'opacity-60 cursor-not-allowed' : ''}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-gateway">Gateway</Label>
              <Input
                id="pool-gateway"
                value={form.gateway}
                onChange={(e) => setForm((f) => ({ ...f, gateway: e.target.value }))}
                placeholder="10.0.0.1"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-zone">Zone</Label>
              <Input
                id="pool-zone"
                value={form.zone}
                onChange={(e) => setForm((f) => ({ ...f, zone: e.target.value }))}
                placeholder="trusted"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-description">Description</Label>
              <Input
                id="pool-description"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="Production network pool"
              />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setFormOpen(false)}>
              Cancel
            </Button>
            <Button
              type="button"
              disabled={
                (!editTarget && (!form.name.trim() || !form.cidr.trim())) || submitting
              }
              onClick={handleSubmit}
            >
              {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editTarget ? 'Save Changes' : 'Create Pool'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm dialog */}
      <Dialog
        open={deleteConfirmOpen}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteConfirmOpen(false);
            setDeleteTarget(null);
            setDeleteError(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Pool: {deleteTarget?.name}</DialogTitle>
            <DialogDescription>
              This pool will be deleted. If it has active allocations, the server will reject
              the request — release all allocations first.
            </DialogDescription>
          </DialogHeader>
          {deleteError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Delete Failed</AlertTitle>
              <AlertDescription>{deleteError}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setDeleteConfirmOpen(false);
                setDeleteTarget(null);
                setDeleteError(null);
              }}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              onClick={handleDelete}
              disabled={deleting}
            >
              {deleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Allocations panel */}
      <Dialog
        open={allocationsOpen}
        onOpenChange={(open) => {
          if (!open) {
            setAllocationsOpen(false);
            setAllocationsPool(null);
            setAllocations([]);
          }
        }}
      >
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              Allocations: {allocationsPool?.name} ({allocationsPool?.cidr})
            </DialogTitle>
            <DialogDescription>
              Active IP allocations in this pool.
            </DialogDescription>
          </DialogHeader>
          {allocationsLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin mr-2" />
              <span>Loading allocations...</span>
            </div>
          ) : allocations.length === 0 ? (
            <p className="text-center text-muted-foreground py-8">No active allocations.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>IP</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Hostname</TableHead>
                  <TableHead>Allocated At</TableHead>
                  <TableHead>Expires</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {allocations.map((a) => (
                  <TableRow key={a.ip}>
                    <TableCell className="font-mono text-sm">{a.ip}</TableCell>
                    <TableCell className="font-mono text-xs">{a.device_id}</TableCell>
                    <TableCell>{a.hostname || '—'}</TableCell>
                    <TableCell className="text-xs">
                      {a.allocated_at ? new Date(a.allocated_at).toLocaleString() : '—'}
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.expires_at ? new Date(a.expires_at).toLocaleString() : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                setAllocationsOpen(false);
                setAllocationsPool(null);
                setAllocations([]);
              }}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
