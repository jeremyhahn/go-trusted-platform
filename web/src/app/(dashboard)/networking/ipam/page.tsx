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
import { useSDNIPAMPools, type SDNIPAMAllocation, type SDNIPAMPool } from '@/hooks/use-sdn-ipam-pools';
import { Gated } from '@/components/features/capabilities/gated';

// The pool as SDNService answers it (pkg/webservice/v1/rest/gateway/ipam.go).
type IPAMPoolResponse = SDNIPAMPool;

const LIST_POOLS = 'GET /api/v1/sdn/gateway/ipam/pools';
const CREATE_POOL = 'POST /api/v1/sdn/gateway/ipam/pools';
const UPDATE_POOL = 'PUT /api/v1/sdn/gateway/ipam/pools/{id}';
const DELETE_POOL = 'DELETE /api/v1/sdn/gateway/ipam/pools/{id}';
const GET_POOL = 'GET /api/v1/sdn/gateway/ipam/pools/{id}';
const LIST_ALLOCATIONS = 'GET /api/v1/sdn/gateway/ipam/allocations';

interface PoolFormState {
  id: string;
  name: string;
  cidr: string;
  gateway: string;
  zone: string;
  description: string;
  /** Comma-separated reserved prefixes. */
  reserved: string;
  rangeStart: string;
  rangeEnd: string;
}

function emptyPoolForm(): PoolFormState {
  return {
    id: '',
    name: '',
    cidr: '',
    gateway: '',
    zone: '',
    description: '',
    reserved: '',
    rangeStart: '',
    rangeEnd: '',
  };
}

/** splitReserved turns the comma-separated form field into a prefix list. */
function splitReserved(value: string): string[] {
  return value
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
}

/** windowLabel renders a pool's dynamic window for the table. */
function windowLabel(pool: IPAMPoolResponse): string {
  if (pool.range_start && pool.range_end) {
    return `${pool.range_start} – ${pool.range_end}`;
  }
  return 'whole CIDR';
}

function utilization(pool: IPAMPoolResponse): number {
  const total = Number(pool.total);
  const allocated = Number(pool.allocated);
  if (!total) return 0;
  return Math.round((allocated / total) * 100);
}

export default function IPAMPage() {
  const { toast } = useToast();

  const [zoneFilter, setZoneFilter] = React.useState('');
  const {
    pools,
    isLoading: loading,
    error: loadError,
    refetch,
    create: createPool,
    update: updatePool,
    remove: removePool,
    get: getPool,
    listAllocations,
  } = useSDNIPAMPools(zoneFilter || undefined);
  // Unique zone values of the last listing feed the filter dropdown.
  const zoneOptions = React.useMemo(
    () => Array.from(new Set(pools.map((p) => p.zone).filter((z): z is string => Boolean(z)))),
    [pools]
  );

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
  const [allocations, setAllocations] = React.useState<SDNIPAMAllocation[]>([]);
  const [allocationsLoading, setAllocationsLoading] = React.useState(false);
  const [allocationsOpen, setAllocationsOpen] = React.useState(false);
  const [allocationsError, setAllocationsError] = React.useState<string | null>(null);

  const fetchAllocations = React.useCallback(async (pool: IPAMPoolResponse) => {
    setAllocationsPool(pool);
    setAllocations([]);
    setAllocationsError(null);
    setAllocationsLoading(true);
    setAllocationsOpen(true);
    try {
      setAllocations(await listAllocations(pool.id));
    } catch (err) {
      setAllocationsError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setAllocationsLoading(false);
    }
  }, [listAllocations]);

  const closeAllocations = React.useCallback(() => {
    setAllocationsOpen(false);
    setAllocationsPool(null);
    setAllocations([]);
    setAllocationsError(null);
  }, []);

  // Details dialog: one pool read again through GET /pools/{id}.
  const [detailPool, setDetailPool] = React.useState<IPAMPoolResponse | null>(null);
  const [detail, setDetail] = React.useState<IPAMPoolResponse | null>(null);
  const [detailError, setDetailError] = React.useState<string | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);

  const openDetails = React.useCallback(async (pool: IPAMPoolResponse) => {
    setDetailPool(pool);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      setDetail(await getPool(pool.id));
    } catch (err) {
      setDetailError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setDetailLoading(false);
    }
  }, [getPool]);

  const closeDetails = React.useCallback(() => {
    setDetailPool(null);
    setDetail(null);
    setDetailError(null);
  }, []);

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
      reserved: (pool.reserved ?? []).join(', '),
      rangeStart: pool.range_start ?? '',
      rangeEnd: pool.range_end ?? '',
    });
    setFormOpen(true);
  }, []);

  const handleSubmit = React.useCallback(async () => {
    if (!editTarget && (!form.name.trim() || !form.cidr.trim())) return;
    setSubmitting(true);
    try {
      if (editTarget) {
        // CIDR is immutable — exclude it from update body
        // The window fields are always sent, so the dialog replaces the
        // pool's window with exactly what it shows.
        const body = {
          name: form.name,
          gateway: form.gateway,
          zone: form.zone,
          description: form.description,
          reserved: splitReserved(form.reserved),
          range_start: form.rangeStart.trim(),
          range_end: form.rangeEnd.trim(),
        };
        await updatePool(editTarget.id, body);
        toast({ title: 'Pool updated', variant: 'success' });
      } else {
        const body = {
          id: form.id || undefined,
          name: form.name,
          cidr: form.cidr,
          gateway: form.gateway || undefined,
          zone: form.zone || undefined,
          description: form.description || undefined,
          reserved: form.reserved.trim() ? splitReserved(form.reserved) : undefined,
          range_start: form.rangeStart.trim() || undefined,
          range_end: form.rangeEnd.trim() || undefined,
        };
        await createPool(body);
        toast({ title: 'Pool created', variant: 'success' });
      }
      setFormOpen(false);
    } catch (err) {
      toast({
        title: editTarget ? 'Failed to update pool' : 'Failed to create pool',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  }, [form, editTarget, createPool, updatePool, toast]);

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
      await removePool(deleteTarget.id);
      toast({ title: 'Pool deleted', variant: 'success' });
      setDeleteConfirmOpen(false);
      setDeleteTarget(null);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, removePool, toast]);

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
        id: 'window',
        header: 'Dynamic window',
        cell: ({ row }) => {
          const pool = row.original;
          return (
            <div className="flex flex-col">
              <span className="font-mono text-xs">{windowLabel(pool)}</span>
              {(pool.reserved ?? []).length > 0 && (
                <span className="font-mono text-xs text-muted-foreground">
                  reserved {(pool.reserved ?? []).join(', ')}
                </span>
              )}
            </div>
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
              { label: 'Edit', onClick: openEdit, op: UPDATE_POOL },
              { label: 'Details', onClick: openDetails, op: GET_POOL },
              {
                label: 'View Allocations',
                onClick: fetchAllocations,
                op: LIST_ALLOCATIONS,
              },
              {
                label: 'Delete',
                onClick: openDeleteConfirm,
                variant: 'destructive',
                separator: true,
                op: DELETE_POOL,
              },
            ]}
          />
        ),
      },
    ],
    [openEdit, openDeleteConfirm, fetchAllocations, openDetails]
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
              onClick={() => void refetch()}
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
          <Gated op={LIST_POOLS}>
            <Button
              type="button"
              variant="outline"
              size="icon"
              aria-label="Refresh pools"
              onClick={() => void refetch()}
              disabled={loading}
            >
              <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            </Button>
          </Gated>
          <Gated op={CREATE_POOL}>
            <Button type="button" onClick={openCreate}>
              <Plus className="mr-2 h-4 w-4" />
              Create Pool
            </Button>
          </Gated>
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
                placeholder="10.4.6.1"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-zone">Zone</Label>
              <Input
                id="pool-zone"
                value={form.zone}
                onChange={(e) => setForm((f) => ({ ...f, zone: e.target.value }))}
                placeholder="control-plane"
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="pool-reserved">Reserved prefixes</Label>
              <Input
                id="pool-reserved"
                value={form.reserved}
                onChange={(e) => setForm((f) => ({ ...f, reserved: e.target.value }))}
                placeholder="10.4.6.1/32, 10.4.6.8/30"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="pool-range-start">Range start</Label>
                <Input
                  id="pool-range-start"
                  value={form.rangeStart}
                  onChange={(e) => setForm((f) => ({ ...f, rangeStart: e.target.value }))}
                  placeholder="10.4.6.50"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="pool-range-end">Range end</Label>
                <Input
                  id="pool-range-end"
                  value={form.rangeEnd}
                  onChange={(e) => setForm((f) => ({ ...f, rangeEnd: e.target.value }))}
                  placeholder="10.4.6.254"
                />
              </div>
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
            <Gated op={editTarget ? UPDATE_POOL : CREATE_POOL}>
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
            </Gated>
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
            <Gated op={DELETE_POOL}>
            <Button
              type="button"
              variant="destructive"
              onClick={handleDelete}
              disabled={deleting}
            >
              {deleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Delete
            </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Pool details */}
      <Dialog
        open={detailPool !== null}
        onOpenChange={(open) => {
          if (!open) closeDetails();
        }}
      >
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Pool {detailPool?.name}</DialogTitle>
            <DialogDescription>The pool as the server answers it now.</DialogDescription>
          </DialogHeader>
          {detailLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin mr-2" />
              <span>Loading pool...</span>
            </div>
          ) : detailError ? (
            <Alert variant="destructive" data-testid="ipam-pool-detail-error">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Failed to load pool</AlertTitle>
              <AlertDescription>{detailError}</AlertDescription>
            </Alert>
          ) : detail ? (
            <dl data-testid="ipam-pool-detail" className="grid grid-cols-2 gap-2 text-sm">
              <dt className="text-muted-foreground">Name</dt>
              <dd>{detail.name}</dd>
              <dt className="text-muted-foreground">CIDR</dt>
              <dd className="font-mono">{detail.cidr}</dd>
              <dt className="text-muted-foreground">Zone</dt>
              <dd>{detail.zone || '—'}</dd>
              <dt className="text-muted-foreground">Gateway</dt>
              <dd className="font-mono">{detail.gateway || '—'}</dd>
              <dt className="text-muted-foreground">Dynamic window</dt>
              <dd className="font-mono">{windowLabel(detail)}</dd>
              <dt className="text-muted-foreground">Total</dt>
              <dd className="font-mono">{detail.total}</dd>
              <dt className="text-muted-foreground">Used</dt>
              <dd className="font-mono">{detail.allocated}</dd>
              <dt className="text-muted-foreground">Available</dt>
              <dd className="font-mono">{detail.available}</dd>
            </dl>
          ) : null}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={closeDetails}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Allocations panel */}
      <Dialog
        open={allocationsOpen}
        onOpenChange={(open) => {
          if (!open) closeAllocations();
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
          ) : allocationsError ? (
            <Alert variant="destructive" data-testid="ipam-allocations-error">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Failed to load allocations</AlertTitle>
              <AlertDescription>{allocationsError}</AlertDescription>
            </Alert>
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
                    <TableCell className="font-mono text-xs">{a.device_id || '—'}</TableCell>
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
              onClick={closeAllocations}
            >
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
