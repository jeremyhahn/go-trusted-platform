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
import { unwrapPayload } from '@/hooks/use-gateway-bgp';
import { gatewayNotConfigured } from '@/hooks/use-gateway-ops';
import { useGateway } from 'trusted-platform-sdk';
import type { ApiResponse } from 'trusted-platform-sdk';

// uint64 arrives as JSON string — render as-is, never parseInt
type Uint64String = string;

type Raw = Record<string, unknown>;

/** The SDK error of a failed reply: its message, or the HTTP status. */
interface SdkError {
  message?: string;
  status?: number;
}

/** IPAMCallError carries an SDK failure and whether it is "not configured". */
class IPAMCallError extends Error {
  constructor(message: string, readonly notConfigured: boolean) {
    super(message);
  }
}

/**
 * sdkCall settles one SDK gateway call: the reply's payload, or an
 * IPAMCallError with the SDK error message (the HTTP status when the
 * server sent none) and the not-configured mark.
 */
async function sdkCall<T>(call: () => Promise<ApiResponse<T>>): Promise<unknown> {
  let res: ApiResponse<T>;
  try {
    res = await call();
  } catch (err) {
    const e = err as SdkError;
    throw new IPAMCallError(
      e?.message || (e?.status ? `HTTP ${e.status}` : 'Unknown error'),
      gatewayNotConfigured(err)
    );
  }
  if (!res.success) {
    const e = res.error as SdkError | undefined;
    throw new IPAMCallError(
      e?.message || (e?.status ? `HTTP ${e.status}` : 'Unknown error'),
      gatewayNotConfigured(res.error)
    );
  }
  return unwrapPayload(res.data);
}

function listOf(body: unknown, key: string): Raw[] {
  if (body && typeof body === 'object') {
    const v = (body as Raw)[key];
    if (Array.isArray(v)) return v.filter((x): x is Raw => !!x && typeof x === 'object');
  }
  return [];
}

function text(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

/** toPool reads a pool in its proto (snake_case) or lowerCamelCase names. */
function toPool(r: Raw): IPAMPoolResponse {
  const pick = (camel: string, snake: string) => r[camel] ?? r[snake];
  const reserved = r.reserved;
  return {
    id: text(r.id),
    name: text(r.name),
    cidr: text(r.cidr),
    gateway: text(r.gateway),
    zone: text(r.zone),
    description: text(r.description),
    total: text(r.total),
    allocated: text(r.allocated),
    available: text(r.available),
    default_lease_duration_nanos: Number(pick('defaultLeaseDurationNanos', 'default_lease_duration_nanos') ?? 0),
    inactivity_timeout_nanos: Number(pick('inactivityTimeoutNanos', 'inactivity_timeout_nanos') ?? 0),
    reserved: Array.isArray(reserved) ? reserved.map(text) : undefined,
    range_start: text(pick('rangeStart', 'range_start')),
    range_end: text(pick('rangeEnd', 'range_end')),
    created_at: text(pick('createdAt', 'created_at')),
    updated_at: text(pick('updatedAt', 'updated_at')),
  };
}

/** toAllocationRow reads an allocation in either naming. */
function toAllocationRow(r: Raw): IPAllocationResponse {
  const pick = (camel: string, snake: string) => text(r[camel] ?? r[snake]);
  return {
    ip: text(r.ip),
    pool_id: pick('poolId', 'pool_id'),
    device_id: pick('deviceId', 'device_id'),
    hostname: text(r.hostname),
    allocated_at: pick('allocatedAt', 'allocated_at'),
    expires_at: pick('expiresAt', 'expires_at'),
  };
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

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
  /** Prefixes (CIDR) that are never allocatable; the gateway is always reserved. */
  reserved?: string[];
  /** Dynamic allocation window; both empty means the whole CIDR. */
  range_start?: string;
  range_end?: string;
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
  const gateway = useGateway();

  // Set when the server answers "not configured": create, edit and delete
  // are disabled with this reason and never reach the SDK.
  const [gatedReason, setGatedReason] = React.useState<string | null>(null);

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

  // Sequence of the latest pool read: a superseded read's answer is dropped.
  const poolSeq = React.useRef(0);

  // settlePools applies one pool read from its promise callbacks, so the
  // effect starts it without a synchronous setState. The zone handler sets
  // loading in its event handler and fetchPools adds the loading reset for
  // a re-read; an older read that answers late is dropped (it neither fills
  // the table nor clears loading).
  const settlePools = React.useCallback((zone?: string) => {
    const seq = ++poolSeq.current;
    // The SDK pool list carries every pool; the zone filter applies here.
    return sdkCall(() => gateway.listIPAMPools())
      .then((body) => {
        if (seq !== poolSeq.current) return;
        const all = listOf(body, 'pools').map(toPool);
        setPools(zone ? all.filter((p) => p.zone === zone) : all);
        // Collect unique zone values for the filter dropdown
        const seenZones = Array.from(new Set(all.map((p) => p.zone).filter(Boolean)));
        setZoneOptions(seenZones);
        setLoadError(null);
      })
      .catch((err: unknown) => {
        if (seq !== poolSeq.current) return;
        if (err instanceof IPAMCallError && err.notConfigured) {
          // A node without the gateway IPAM: show the page with every
          // write gated off and the reason, not a load failure.
          setPools([]);
          setGatedReason(`IPAM is not available on this node: ${err.message}`);
          setLoadError(null);
          return;
        }
        setLoadError(errorText(err));
      })
      .finally(() => {
        if (seq !== poolSeq.current) return;
        setLoading(false);
      });
  }, [gateway]);

  const fetchPools = React.useCallback(
    async (zone?: string) => {
      setLoading(true);
      setLoadError(null);
      await settlePools(zone);
    },
    [settlePools]
  );

  React.useEffect(() => {
    void settlePools(zoneFilter || undefined);
  }, [settlePools, zoneFilter]);

  const fetchAllocations = React.useCallback(async (pool: IPAMPoolResponse) => {
    setAllocationsPool(pool);
    setAllocationsLoading(true);
    setAllocationsOpen(true);
    try {
      const body = await sdkCall(() => gateway.listAllocations({ poolId: pool.id }));
      setAllocations(listOf(body, 'allocations').map(toAllocationRow));
    } catch (err) {
      toast({
        title: 'Failed to load allocations',
        description: errorText(err),
        variant: 'destructive',
      });
      setAllocations([]);
    } finally {
      setAllocationsLoading(false);
    }
  }, [gateway, toast]);

  const openCreate = React.useCallback(() => {
    if (gatedReason) return;
    setEditTarget(null);
    setForm(emptyPoolForm());
    setFormOpen(true);
  }, [gatedReason]);

  const openEdit = React.useCallback((pool: IPAMPoolResponse) => {
    if (gatedReason) return;
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
  }, [gatedReason]);

  const handleSubmit = React.useCallback(async () => {
    if (gatedReason) return;
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
        // UpdateIPAMPool keeps the CIDR; the SDK request type requires one.
        await sdkCall(() =>
          gateway.updateIPAMPool(editTarget.id, body as Parameters<typeof gateway.updateIPAMPool>[1])
        );
        toast({ title: 'Pool updated', variant: 'success' });
      } else {
        const body: Parameters<typeof gateway.createIPAMPool>[0] = {
          name: form.name,
          cidr: form.cidr,
        };
        if (form.gateway) body.gateway = form.gateway;
        if (form.zone) body.zone = form.zone;
        if (form.description) body.description = form.description;
        if (form.reserved.trim()) body.reserved = splitReserved(form.reserved);
        if (form.rangeStart.trim()) body.range_start = form.rangeStart.trim();
        if (form.rangeEnd.trim()) body.range_end = form.rangeEnd.trim();
        await sdkCall(() => gateway.createIPAMPool(body));
        toast({ title: 'Pool created', variant: 'success' });
      }
      setFormOpen(false);
      void fetchPools(zoneFilter || undefined);
    } catch (err) {
      if (err instanceof IPAMCallError && err.notConfigured) {
        setGatedReason(`IPAM is not available on this node: ${err.message}`);
      }
      toast({
        title: editTarget ? 'Failed to update pool' : 'Failed to create pool',
        description: errorText(err),
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  }, [form, editTarget, fetchPools, zoneFilter, toast, gateway, gatedReason]);

  const openDeleteConfirm = React.useCallback((pool: IPAMPoolResponse) => {
    if (gatedReason) return;
    setDeleteTarget(pool);
    setDeleteError(null);
    setDeleteConfirmOpen(true);
  }, [gatedReason]);

  const handleDelete = React.useCallback(async () => {
    if (!deleteTarget || gatedReason) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await sdkCall(() => gateway.deleteIPAMPool(deleteTarget.id));
      toast({ title: 'Pool deleted', variant: 'success' });
      setDeleteConfirmOpen(false);
      setDeleteTarget(null);
      void fetchPools(zoneFilter || undefined);
    } catch (err) {
      if (err instanceof IPAMCallError && err.notConfigured) {
        setGatedReason(`IPAM is not available on this node: ${err.message}`);
      }
      setDeleteError(errorText(err));
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, fetchPools, zoneFilter, toast, gateway, gatedReason]);

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
          <Button type="button" onClick={openCreate} disabled={!!gatedReason}>
            <Plus className="mr-2 h-4 w-4" />
            Create Pool
          </Button>
          {gatedReason && (
            <span role="note" className="text-sm text-muted-foreground">
              {gatedReason}
            </span>
          )}
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
                onValueChange={(v) => {
                  const next = v === '__all__' ? '' : v;
                  if (next === zoneFilter) return;
                  setLoading(true);
                  setZoneFilter(next);
                }}
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
