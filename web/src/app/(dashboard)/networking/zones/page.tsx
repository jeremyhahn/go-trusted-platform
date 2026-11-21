'use client';

import * as React from 'react';
import { Plus, RefreshCw, Shield, AlertCircle, Loader2, X } from 'lucide-react';
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
import { Switch } from '@/components/ui/switch';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';

// The nine built-in underlay zones of the reference network, at fixed
// offsets x00-x08 of every environment block. Their policy can be tuned;
// their numbering, port classes and lifecycle roles cannot. Owner-defined
// zones take offsets 9-99. Overlays (platform, tenant, public) are not zones.
const BUILTIN_ZONES = new Set([
  'transit',
  'fabric',
  'management',
  'hypervisor',
  'quarantine',
  'provisioning',
  'control-plane',
  'storage',
  'backup',
]);

// Port classes an owner-defined zone may join.
const OWNER_PORT_CLASSES = ['gateway', 'hypervisor'];

// AllowToEntry declares a single egress path: traffic from this zone is
// permitted to flow to the named target zone, optionally restricted to the
// listed services (empty list = all services).
interface AllowToEntry {
  zone: string;
  services?: string[];
}

// PrivilegedAccess is the audited override required for an allow_to path
// into control-plane or management beyond the reference defaults.
interface PrivilegedAccess {
  reason: string;
  approved_by: string;
}

// ZoneNumbering is the zone's numbering derived from the node's environment.
interface ZoneNumbering {
  vlan: number;
  subnet4: string;
  subnet6?: string;
  gateway: string;
}

interface ZoneResponse {
  name: string;
  offset: number;
  port_classes: string[];
  internet_ingress: boolean;
  isolate_from: string[];
  allow_to: AllowToEntry[];
  services: string[];
  isolate: boolean;
  oob: boolean;
  lifecycle_role: string;
  privileged_access?: PrivilegedAccess;
  numbering?: ZoneNumbering;
  restart_required: boolean;
  created_at: string;
  updated_at: string;
}

interface ZoneFormState {
  name: string;
  offset: number;
  port_classes: string[];
  internet_ingress: boolean;
  isolate_from: string[];
  allow_to: AllowToEntry[];
  services: string[];
  isolate: boolean;
  oob: boolean;
  lifecycle_role: string;
  privileged_reason: string;
  privileged_approved_by: string;
}

function emptyForm(): ZoneFormState {
  return {
    name: '',
    offset: 9,
    port_classes: ['hypervisor'],
    internet_ingress: false,
    isolate_from: [],
    allow_to: [],
    services: [],
    isolate: true,
    oob: false,
    lifecycle_role: '',
    privileged_reason: '',
    privileged_approved_by: '',
  };
}

// zoneBody renders the form as the REST zone body (pkg/sdn/gateway.ZoneSpec).
function zoneBody(form: ZoneFormState, includeName: boolean): Record<string, unknown> {
  const body: Record<string, unknown> = {
    offset: form.offset,
    port_classes: form.port_classes,
    internet_ingress: form.internet_ingress,
    isolate_from: form.isolate_from,
    allow_to: form.allow_to,
    services: form.services,
    isolate: form.isolate,
    oob: form.oob,
    lifecycle_role: form.lifecycle_role,
  };
  if (includeName) body.name = form.name;
  if (form.privileged_reason || form.privileged_approved_by) {
    body.privileged_access = {
      reason: form.privileged_reason,
      approved_by: form.privileged_approved_by,
    };
  }
  return body;
}

// parseCSV splits a comma-separated string into a trimmed, non-empty string
// array used for the services tag input.
function parseCSV(raw: string): string[] {
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// AllowToRow is a single editable row in the allow_to editor.
interface AllowToRowProps {
  entry: AllowToEntry;
  index: number;
  zoneNames: string[];
  currentZoneName: string;
  usedZones: Set<string>;
  onChange: (index: number, entry: AllowToEntry) => void;
  onRemove: (index: number) => void;
}

function AllowToRow({
  entry,
  index,
  zoneNames,
  currentZoneName,
  usedZones,
  onChange,
  onRemove,
}: AllowToRowProps) {
  const [svcInput, setSvcInput] = React.useState(
    (entry.services ?? []).join(', ')
  );

  const handleZoneChange = React.useCallback(
    (zone: string) => {
      onChange(index, { ...entry, zone: zone === '__pick__' ? '' : zone });
    },
    [index, entry, onChange]
  );

  const handleServicesBlur = React.useCallback(() => {
    onChange(index, { ...entry, services: parseCSV(svcInput) });
  }, [index, entry, svcInput, onChange]);

  // Available zone names: exclude the current zone, already-used zones
  // (except this row's own selection so it can be re-selected).
  const available = zoneNames.filter(
    (n) => n !== currentZoneName && (!usedZones.has(n) || n === entry.zone)
  );

  return (
    <div className="flex gap-2 items-start">
      <Select value={entry.zone || '__pick__'} onValueChange={handleZoneChange}>
        <SelectTrigger className="w-[160px] shrink-0">
          <SelectValue placeholder="Select zone..." />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="__pick__">Select zone...</SelectItem>
          {available.map((n) => (
            <SelectItem key={n} value={n}>
              {n}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <Input
        className="flex-1"
        placeholder="services (CSV, empty = all)"
        value={svcInput}
        onChange={(e) => setSvcInput(e.target.value)}
        onBlur={handleServicesBlur}
      />
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="shrink-0"
        onClick={() => onRemove(index)}
        aria-label="Remove allow_to entry"
      >
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

export default function ZonesPage() {
  const { toast } = useToast();

  const [zones, setZones] = React.useState<ZoneResponse[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<string | null>(null);

  const [formOpen, setFormOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<ZoneResponse | null>(null);
  const [form, setForm] = React.useState<ZoneFormState>(emptyForm());
  const [isolateFromInput, setIsolateFromInput] = React.useState('');
  const [servicesInput, setServicesInput] = React.useState('');
  const [submitting, setSubmitting] = React.useState(false);

  const [deleteTarget, setDeleteTarget] = React.useState<ZoneResponse | null>(null);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState<string | null>(null);
  const [deleting, setDeleting] = React.useState(false);

  // settleZones applies one zone read from its promise callbacks, so the
  // effect starts it without a synchronous setState; fetchZones adds the
  // loading reset for a re-read.
  const settleZones = React.useCallback(
    () =>
      fetch('/api/v1/sdn/zones', { credentials: 'include' })
        .then(async (res) => {
          if (!res.ok) {
            const body = await res.json().catch(() => ({}));
            throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
          }
          // The webservice wraps payloads in {payload}; the daemon REST
          // stack returns the body bare — accept both.
          const body = (await res.json()) as {
            zones?: ZoneResponse[];
            payload?: { zones?: ZoneResponse[] };
          };
          setZones(body.payload?.zones ?? body.zones ?? []);
          setLoadError(null);
        })
        .catch((err: unknown) => {
          setLoadError(err instanceof Error ? err.message : String(err));
        })
        .finally(() => setLoading(false)),
    []
  );

  const fetchZones = React.useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    await settleZones();
  }, [settleZones]);

  React.useEffect(() => {
    void settleZones();
  }, [settleZones]);

  const zoneNames = React.useMemo(() => zones.map((z) => z.name), [zones]);

  // Set of zones already referenced in allow_to so each target appears at
  // most once per row (duplicate rows for the same target zone are still
  // allowed by the backend, but would be confusing in the UI).
  const allowToUsedZones = React.useMemo(
    () => new Set(form.allow_to.map((e) => e.zone).filter(Boolean)),
    [form.allow_to]
  );

  const openCreate = React.useCallback(() => {
    setEditTarget(null);
    setForm(emptyForm());
    setIsolateFromInput('');
    setServicesInput('');
    setFormOpen(true);
  }, []);

  const openEdit = React.useCallback((zone: ZoneResponse) => {
    setEditTarget(zone);
    setForm({
      name: zone.name,
      offset: zone.offset ?? 0,
      port_classes: zone.port_classes ?? [],
      internet_ingress: zone.internet_ingress ?? false,
      isolate_from: zone.isolate_from ?? [],
      allow_to: zone.allow_to ?? [],
      services: zone.services ?? [],
      isolate: zone.isolate ?? false,
      oob: zone.oob ?? false,
      lifecycle_role: zone.lifecycle_role ?? '',
      privileged_reason: zone.privileged_access?.reason ?? '',
      privileged_approved_by: zone.privileged_access?.approved_by ?? '',
    });
    setIsolateFromInput('');
    setServicesInput('');
    setFormOpen(true);
  }, []);

  const handleSubmit = React.useCallback(async () => {
    if (!editTarget && !form.name.trim()) return;
    setSubmitting(true);
    try {
      if (editTarget) {
        const res = await fetch(
          `/api/v1/sdn/zones/${encodeURIComponent(editTarget.name)}`,
          {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(zoneBody(form, false)),
          }
        );
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
        }
        toast({ title: 'Zone updated', variant: 'success' });
      } else {
        const res = await fetch('/api/v1/sdn/zones', {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(zoneBody(form, true)),
        });
        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
        }
        toast({ title: 'Zone created', variant: 'success' });
      }
      setFormOpen(false);
      void fetchZones();
    } catch (err) {
      toast({
        title: editTarget ? 'Failed to update zone' : 'Failed to create zone',
        description: err instanceof Error ? err.message : 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  }, [form, editTarget, fetchZones, toast]);

  const openDeleteConfirm = React.useCallback((zone: ZoneResponse) => {
    setDeleteTarget(zone);
    setDeleteError(null);
    setDeleteConfirmOpen(true);
  }, []);

  const handleDelete = React.useCallback(async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      const res = await fetch(
        `/api/v1/sdn/zones/${encodeURIComponent(deleteTarget.name)}`,
        {
          method: 'DELETE',
          credentials: 'include',
        }
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
      }
      toast({ title: 'Zone deleted', variant: 'success' });
      setDeleteConfirmOpen(false);
      setDeleteTarget(null);
      void fetchZones();
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, fetchZones, toast]);

  // isolate_from helpers
  const addIsolateFrom = React.useCallback(() => {
    const name = isolateFromInput.trim();
    if (!name || form.isolate_from.includes(name)) return;
    setForm((f) => ({ ...f, isolate_from: [...f.isolate_from, name] }));
    setIsolateFromInput('');
  }, [isolateFromInput, form.isolate_from]);

  const removeIsolateFrom = React.useCallback((name: string) => {
    setForm((f) => ({ ...f, isolate_from: f.isolate_from.filter((z) => z !== name) }));
  }, []);

  // services helpers
  const commitServicesInput = React.useCallback(() => {
    const tags = parseCSV(servicesInput);
    if (tags.length === 0) return;
    setForm((f) => ({
      ...f,
      services: [...new Set([...f.services, ...tags])],
    }));
    setServicesInput('');
  }, [servicesInput]);

  const handleServicesKeyDown = React.useCallback(
    (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault();
        commitServicesInput();
      }
    },
    [commitServicesInput]
  );

  const removeService = React.useCallback((svc: string) => {
    setForm((f) => ({ ...f, services: f.services.filter((s) => s !== svc) }));
  }, []);

  // allow_to helpers
  const addAllowToRow = React.useCallback(() => {
    setForm((f) => ({ ...f, allow_to: [...f.allow_to, { zone: '', services: [] }] }));
  }, []);

  const updateAllowToRow = React.useCallback((index: number, entry: AllowToEntry) => {
    setForm((f) => {
      const next = [...f.allow_to];
      next[index] = entry;
      return { ...f, allow_to: next };
    });
  }, []);

  const removeAllowToRow = React.useCallback((index: number) => {
    setForm((f) => ({ ...f, allow_to: f.allow_to.filter((_, i) => i !== index) }));
  }, []);

  const columns: ColumnDef<ZoneResponse>[] = React.useMemo(
    () => [
      createSelectColumn<ZoneResponse>(),
      {
        accessorKey: 'name',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => {
          const name = row.getValue('name') as string;
          const isBuiltin = BUILTIN_ZONES.has(name);
          return (
            <div className="flex items-center gap-2">
              <span className="font-medium font-mono">{name}</span>
              {isBuiltin && (
                <Badge variant="secondary" className="text-xs">
                  built-in
                </Badge>
              )}
            </div>
          );
        },
      },
      {
        accessorKey: 'offset',
        header: ({ column }) => <DataTableColumnHeader column={column} title="Offset" />,
        cell: ({ row }) => (
          <span className="font-mono text-xs">x{String(row.original.offset ?? 0).padStart(2, '0')}</span>
        ),
      },
      {
        id: 'numbering',
        header: 'VLAN / Subnet',
        cell: ({ row }) => {
          const n = row.original.numbering;
          return n ? (
            <span className="font-mono text-xs">
              {n.vlan} · {n.subnet4}
            </span>
          ) : (
            <span className="text-muted-foreground text-xs">—</span>
          );
        },
      },
      {
        accessorKey: 'lifecycle_role',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Lifecycle Role" />
        ),
        cell: ({ row }) => {
          const role = row.getValue('lifecycle_role') as string;
          if (!role) return <span className="text-muted-foreground">—</span>;
          const colorMap: Record<string, string> = {
            provisioning: 'bg-blue-500/10 text-blue-500 border-blue-500/20',
            quarantine: 'bg-orange-500/10 text-orange-500 border-orange-500/20',
          };
          return (
            <Badge variant="outline" className={colorMap[role] ?? ''}>
              {role}
            </Badge>
          );
        },
        filterFn: (row, id, value) => (value as string[]).includes(row.getValue(id)),
      },
      {
        id: 'policy_summary',
        header: 'Policy Flags',
        cell: ({ row }) => {
          const z = row.original;
          const flags: string[] = [];
          if (z.internet_ingress) flags.push('internet-ingress');
          if (z.isolate) flags.push('isolate');
          if (z.oob) flags.push('oob');
          if (z.privileged_access) flags.push('privileged-access');
          if ((z.isolate_from ?? []).length > 0)
            flags.push(`isolate-from(${z.isolate_from.length})`);
          if ((z.allow_to ?? []).length > 0)
            flags.push(`allow-to(${z.allow_to.length})`);
          if ((z.services ?? []).length > 0)
            flags.push(`services(${z.services.length})`);
          return flags.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {flags.map((f) => (
                <Badge key={f} variant="outline" className="text-xs">
                  {f}
                </Badge>
              ))}
            </div>
          ) : (
            <span className="text-muted-foreground text-xs">default</span>
          );
        },
      },
      {
        accessorKey: 'updated_at',
        header: ({ column }) => (
          <DataTableColumnHeader column={column} title="Updated" />
        ),
        cell: ({ row }) => {
          const val = row.getValue('updated_at') as string;
          return val ? (
            <span className="text-xs text-muted-foreground">
              {new Date(val).toLocaleString()}
            </span>
          ) : (
            <span className="text-muted-foreground">—</span>
          );
        },
      },
      {
        id: 'actions',
        cell: ({ row }) => {
          const zone = row.original;
          const isBuiltin = BUILTIN_ZONES.has(zone.name);
          return (
            <DataTableRowActions
              row={zone}
              actions={[
                {
                  label: isBuiltin ? 'Override (Edit)' : 'Edit',
                  onClick: openEdit,
                },
                {
                  label: 'Delete',
                  onClick: openDeleteConfirm,
                  variant: 'destructive',
                  separator: true,
                },
              ]}
            />
          );
        },
      },
    ],
    [openEdit, openDeleteConfirm]
  );

  const stats = React.useMemo(
    () => ({
      total: zones.length,
      builtin: zones.filter((z) => BUILTIN_ZONES.has(z.name)).length,
      custom: zones.filter((z) => !BUILTIN_ZONES.has(z.name)).length,
      lifecycle: zones.filter((z) => !!z.lifecycle_role).length,
      isolated: zones.filter((z) => z.isolate).length,
    }),
    [zones]
  );

  if (loadError && zones.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Zones</AlertTitle>
          <AlertDescription>
            {loadError}
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="ml-4"
              onClick={fetchZones}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  if (loading && zones.length === 0) {
    return (
      <div className="container mx-auto py-6">
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading zones...</span>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Network Zones</h1>
          <p className="text-muted-foreground mt-1">
            Configure zone-based network segmentation and traffic policy
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            type="button"
            variant="outline"
            size="icon"
            onClick={fetchZones}
            disabled={loading}
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          </Button>
          <Button type="button" onClick={openCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Create Zone
          </Button>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-5">
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Total</div>
          <div className="text-3xl font-bold mt-2">{stats.total}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Built-in</div>
          <div className="text-3xl font-bold mt-2 text-blue-500">{stats.builtin}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Custom</div>
          <div className="text-3xl font-bold mt-2 text-green-500">{stats.custom}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Lifecycle Roles</div>
          <div className="text-3xl font-bold mt-2 text-orange-500">{stats.lifecycle}</div>
        </div>
        <div className="rounded-lg border border-border bg-card p-6">
          <div className="text-sm font-medium text-muted-foreground">Isolated</div>
          <div className="text-3xl font-bold mt-2 text-yellow-500">{stats.isolated}</div>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Network Zones
          </CardTitle>
        </CardHeader>
        <CardContent>
          <DataTable
            columns={columns}
            data={zones}
            loading={loading}
            searchKey="name"
            searchPlaceholder="Search zones..."
            filterableColumns={[
              {
                id: 'lifecycle_role',
                title: 'Lifecycle Role',
                options: [
                  { label: 'Provisioning', value: 'provisioning' },
                  { label: 'Quarantine', value: 'quarantine' },
                  { label: 'None', value: '' },
                ],
              },
            ]}
            pagination
            pageSize={20}
          />
        </CardContent>
      </Card>

      {/* Create / Edit dialog */}
      <Dialog open={formOpen} onOpenChange={setFormOpen}>
        <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editTarget
                ? BUILTIN_ZONES.has(editTarget.name)
                  ? `Override Built-in Zone: ${editTarget.name}`
                  : `Edit Zone: ${editTarget.name}`
                : 'Create Zone'}
            </DialogTitle>
            <DialogDescription>
              {editTarget && BUILTIN_ZONES.has(editTarget.name)
                ? 'Your policy replaces the built-in defaults. The zone keeps its offset, port classes and lifecycle role.'
                : 'An owner-defined zone takes an offset 9-99 and joins the gateway and/or hypervisor port class. The change applies at the next daemon restart.'}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            {!editTarget && (
              <div className="space-y-2">
                <Label htmlFor="zone-name">Name *</Label>
                <Input
                  id="zone-name"
                  value={form.name}
                  onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                  placeholder="my-zone"
                />
              </div>
            )}

            {!(editTarget && BUILTIN_ZONES.has(editTarget.name)) && (
              <div className="space-y-2">
                <Label htmlFor="zone-offset">Offset (9-99)</Label>
                <Input
                  id="zone-offset"
                  type="number"
                  min={9}
                  max={99}
                  value={form.offset}
                  onChange={(e) => setForm((f) => ({ ...f, offset: Number(e.target.value) }))}
                />
                <Label className="text-sm font-medium">Port Classes</Label>
                {OWNER_PORT_CLASSES.map((pc) => (
                  <div key={pc} className="flex items-center gap-3">
                    <Switch
                      id={`port-class-${pc}`}
                      checked={form.port_classes.includes(pc)}
                      onCheckedChange={(v) =>
                        setForm((f) => ({
                          ...f,
                          port_classes: v
                            ? [...f.port_classes.filter((c) => c !== pc), pc]
                            : f.port_classes.filter((c) => c !== pc),
                        }))
                      }
                    />
                    <Label htmlFor={`port-class-${pc}`} className="font-normal cursor-pointer">
                      {pc}
                    </Label>
                  </div>
                ))}
              </div>
            )}

            {/* Flags section */}
            <div className="space-y-3 pt-2 border-t">
              <Label className="text-sm font-medium">Flags</Label>
              <div className="flex items-center gap-3">
                <Switch
                  id="internet-ingress"
                  checked={form.internet_ingress}
                  onCheckedChange={(v) => setForm((f) => ({ ...f, internet_ingress: v }))}
                />
                <Label htmlFor="internet-ingress" className="font-normal cursor-pointer">
                  Internet Ingress
                  <span className="ml-1 text-xs text-muted-foreground">
                    (accepts inbound internet traffic)
                  </span>
                </Label>
              </div>
              <div className="flex items-center gap-3">
                <Switch
                  id="isolate"
                  checked={form.isolate}
                  onCheckedChange={(v) => setForm((f) => ({ ...f, isolate: v }))}
                />
                <Label htmlFor="isolate" className="font-normal cursor-pointer">
                  Isolate
                  <span className="ml-1 text-xs text-muted-foreground">
                    (deny all inter-zone traffic except explicit allow_to paths)
                  </span>
                </Label>
              </div>
            </div>

            {/* Isolate From */}
            <div className="space-y-2 pt-2 border-t">
              <Label>Isolate From Zones</Label>
              <p className="text-xs text-muted-foreground">
                Unconditionally deny traffic from these zones regardless of their allow_to
                declarations.
              </p>
              <div className="flex gap-2">
                <Select
                  value={isolateFromInput || '__pick__'}
                  onValueChange={(v) => setIsolateFromInput(v === '__pick__' ? '' : v)}
                >
                  <SelectTrigger className="flex-1">
                    <SelectValue placeholder="Select zone to exclude..." />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="__pick__">Select zone...</SelectItem>
                    {zoneNames
                      .filter((n) => n !== form.name && !form.isolate_from.includes(n))
                      .map((n) => (
                        <SelectItem key={n} value={n}>
                          {n}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
                <Button
                  type="button"
                  variant="outline"
                  onClick={addIsolateFrom}
                  disabled={!isolateFromInput}
                >
                  Add
                </Button>
              </div>
              {form.isolate_from.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {form.isolate_from.map((z) => (
                    <Badge
                      key={z}
                      variant="secondary"
                      className="cursor-pointer gap-1 hover:bg-destructive/20"
                      onClick={() => removeIsolateFrom(z)}
                    >
                      {z} <span className="text-xs">×</span>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Allow To */}
            <div className="space-y-2 pt-2 border-t">
              <Label>Egress Allow-To</Label>
              <p className="text-xs text-muted-foreground">
                Declare explicit egress paths. Each row names a target zone and an optional
                comma-separated list of permitted services (leave services empty to allow all).
              </p>
              <div className="space-y-2">
                {form.allow_to.map((entry, i) => (
                  <AllowToRow
                    key={i}
                    entry={entry}
                    index={i}
                    zoneNames={zoneNames}
                    currentZoneName={form.name}
                    usedZones={allowToUsedZones}
                    onChange={updateAllowToRow}
                    onRemove={removeAllowToRow}
                  />
                ))}
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={addAllowToRow}
                className="mt-1"
              >
                <Plus className="mr-1 h-3 w-3" />
                Add Egress Path
              </Button>
            </div>

            {/* Intra-zone Services */}
            <div className="space-y-2 pt-2 border-t">
              <Label>Intra-Zone Services</Label>
              <p className="text-xs text-muted-foreground">
                Allowlist for traffic between endpoints inside this zone. Enter service
                names separated by commas and press Enter or comma to add.
              </p>
              <div className="flex gap-2">
                <Input
                  placeholder="e.g. ssh, http, postgres"
                  value={servicesInput}
                  onChange={(e) => setServicesInput(e.target.value)}
                  onKeyDown={handleServicesKeyDown}
                  onBlur={commitServicesInput}
                  className="flex-1"
                />
                <Button
                  type="button"
                  variant="outline"
                  onClick={commitServicesInput}
                  disabled={!servicesInput.trim()}
                >
                  Add
                </Button>
              </div>
              {form.services.length > 0 && (
                <div className="flex flex-wrap gap-2 pt-1">
                  {form.services.map((svc) => (
                    <Badge
                      key={svc}
                      variant="secondary"
                      className="cursor-pointer gap-1 hover:bg-destructive/20"
                      onClick={() => removeService(svc)}
                    >
                      {svc} <span className="text-xs">×</span>
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {/* Privileged access */}
            <div className="space-y-2 pt-2 border-t">
              <Label>Privileged Access</Label>
              <p className="text-xs text-muted-foreground">
                Required, and audited, when allow-to opens a path into control-plane or
                management beyond the reference defaults.
              </p>
              <Input
                id="privileged-reason"
                value={form.privileged_reason}
                onChange={(e) => setForm((f) => ({ ...f, privileged_reason: e.target.value }))}
                placeholder="Reason"
              />
              <Input
                id="privileged-approved-by"
                value={form.privileged_approved_by}
                onChange={(e) => setForm((f) => ({ ...f, privileged_approved_by: e.target.value }))}
                placeholder="Approved by"
              />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setFormOpen(false)}>
              Cancel
            </Button>
            <Button
              type="button"
              disabled={(!editTarget && !form.name.trim()) || submitting}
              onClick={handleSubmit}
            >
              {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {editTarget ? 'Save Changes' : 'Create Zone'}
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
            <DialogTitle>Delete Zone: {deleteTarget?.name}</DialogTitle>
            <DialogDescription>
              {deleteTarget && BUILTIN_ZONES.has(deleteTarget.name)
                ? 'Deleting a built-in zone omits it from this environment. fabric, provisioning, quarantine and control-plane cannot be removed.'
                : 'The zone is removed at the next daemon restart. This action cannot be undone.'}
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
    </div>
  );
}
