'use client';

/**
 * SDNPoliciesPage lists the SDN policies (SDNService ListPolicies) and
 * applies, reads and deletes one (ApplyPolicy, GetPolicy, DeletePolicy), each
 * control behind the capability gate of its /api/v1/sdn/policies route.
 */

import * as React from 'react';
import { AlertCircle, Loader2, Plus, RefreshCw, ShieldCheck, X } from 'lucide-react';
import { ColumnDef } from '@tanstack/react-table';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { DataTable } from '@/components/ui/data-table';
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
import { Gated } from '@/components/features/capabilities/gated';
import { useSDNPolicies, type SDNPolicy } from '@/hooks/use-sdn-policies';

const LIST_POLICIES = 'GET /api/v1/sdn/policies';
const GET_POLICY = 'GET /api/v1/sdn/policies/{id}';
const APPLY_POLICY = 'POST /api/v1/sdn/policies';
const DELETE_POLICY = 'DELETE /api/v1/sdn/policies/{id}';

/** The PolicyType names of pkg/api/grpc/proto/sdn.proto, UNSPECIFIED left out. */
const POLICY_TYPES = [
  'POLICY_TYPE_ACL',
  'POLICY_TYPE_QOS',
  'POLICY_TYPE_NAT',
  'POLICY_TYPE_FIREWALL',
  'POLICY_TYPE_ROUTING',
] as const;

/** shortName strips a proto enum prefix for the table ("POLICY_TYPE_ACL" -> "ACL"). */
function shortName(value: string | undefined, prefix: string): string {
  if (!value) return '-';
  return value.startsWith(prefix) ? value.slice(prefix.length) : value;
}

function policyName(policy: SDNPolicy): string {
  return policy.config?.name || policy.id || '-';
}

interface ApplyFormState {
  policyId: string;
  name: string;
  type: string;
  priority: string;
  enabled: boolean;
}

function emptyApplyForm(): ApplyFormState {
  return { policyId: '', name: '', type: 'POLICY_TYPE_ACL', priority: '100', enabled: true };
}

type Detail =
  | { id: string; loading: true }
  | { id: string; loading: false; policy?: SDNPolicy; error?: string };

export default function SDNPoliciesPage() {
  const { policies, isLoading, error, notConfigured, refetch, get, apply, remove } = useSDNPolicies();

  const [applyOpen, setApplyOpen] = React.useState(false);
  const [form, setForm] = React.useState<ApplyFormState>(emptyApplyForm());
  const [applying, setApplying] = React.useState(false);
  const [applyError, setApplyError] = React.useState<string | null>(null);

  const [detail, setDetail] = React.useState<Detail | null>(null);

  const [deleteTarget, setDeleteTarget] = React.useState<SDNPolicy | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [deleteError, setDeleteError] = React.useState<string | null>(null);

  const openApply = React.useCallback(() => {
    setForm(emptyApplyForm());
    setApplyError(null);
    setApplyOpen(true);
  }, []);

  const handleApply = React.useCallback(async () => {
    const id = form.policyId.trim();
    // ApplyPolicy replaces the whole config, and this form carries no rules
    // or targets: refuse to overwrite a policy that already exists.
    if (policies.some((p) => p.id === id)) {
      setApplyError(
        `Policy ${id} already exists. Replacing it from this form would remove its enforcement rules; delete it first or edit it through the API.`
      );
      return;
    }
    setApplying(true);
    setApplyError(null);
    try {
      const priority = Number.parseInt(form.priority, 10);
      await apply({
        policyId: id,
        config: {
          name: form.name.trim(),
          type: form.type,
          priority: Number.isFinite(priority) ? priority : 0,
          enabled: form.enabled,
        },
      });
      setApplyOpen(false);
    } catch (err) {
      setApplyError(err instanceof Error ? err.message : String(err));
    } finally {
      setApplying(false);
    }
  }, [form, apply, policies]);

  const openDetail = React.useCallback(
    async (policy: SDNPolicy) => {
      const id = policy.id ?? '';
      setDetail({ id, loading: true });
      try {
        const answer = await get(id);
        setDetail((d) => (d?.id === id ? { id, loading: false, policy: answer } : d));
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        setDetail((d) => (d?.id === id ? { id, loading: false, error: message } : d));
      }
    },
    [get]
  );

  const openDelete = React.useCallback((policy: SDNPolicy) => {
    setDeleteError(null);
    setDeleteTarget(policy);
  }, []);

  const handleDelete = React.useCallback(async () => {
    if (!deleteTarget?.id) return;
    setDeleting(true);
    setDeleteError(null);
    try {
      await remove(deleteTarget.id);
      setDeleteTarget(null);
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleting(false);
    }
  }, [deleteTarget, remove]);

  const columns: ColumnDef<SDNPolicy>[] = React.useMemo(
    () => [
      {
        id: 'name',
        accessorFn: (p) => policyName(p),
        header: ({ column }) => <DataTableColumnHeader column={column} title="Name" />,
        cell: ({ row }) => (
          <div className="flex flex-col">
            <span className="font-medium">{policyName(row.original)}</span>
            <span className="font-mono text-xs text-muted-foreground">{row.original.id}</span>
          </div>
        ),
      },
      {
        id: 'type',
        header: 'Type',
        cell: ({ row }) => (
          <Badge variant="outline">{shortName(row.original.config?.type, 'POLICY_TYPE_')}</Badge>
        ),
      },
      {
        id: 'status',
        header: 'Status',
        cell: ({ row }) => (
          <Badge variant="secondary">{shortName(row.original.status, 'POLICY_STATUS_')}</Badge>
        ),
      },
      {
        id: 'priority',
        header: 'Priority',
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.config?.priority ?? 0}</span>,
      },
      {
        id: 'hits',
        header: 'Hits',
        cell: ({ row }) => <span className="font-mono text-sm">{row.original.hitCount ?? '0'}</span>,
      },
      {
        id: 'actions',
        cell: ({ row }) => (
          <DataTableRowActions
            row={row.original}
            actions={[
              { label: 'Details', onClick: (p: SDNPolicy) => void openDetail(p), op: GET_POLICY },
              {
                label: 'Delete',
                onClick: openDelete,
                variant: 'destructive',
                separator: true,
                op: DELETE_POLICY,
              },
            ]}
          />
        ),
      },
    ],
    [openDetail, openDelete]
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">SDN Policies</h1>
          <p className="text-muted-foreground mt-1">ACL, QoS, NAT, firewall and routing policies of the SDN controller</p>
        </div>
        <div className="flex gap-2">
          <Gated op={LIST_POLICIES}>
            <Button type="button" variant="outline" onClick={() => void refetch()} disabled={isLoading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </Gated>
          <Gated op={APPLY_POLICY}>
            <Button type="button" onClick={openApply}>
              <Plus className="mr-2 h-4 w-4" />
              Apply Policy
            </Button>
          </Gated>
        </div>
      </div>

      {notConfigured ? (
        <Card data-testid="sdn-policies-not-configured">
          <CardHeader>
            <CardTitle>SDN is not configured</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            This server runs without an SDN controller, so it has no policies to show.
          </CardContent>
        </Card>
      ) : error ? (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Policies</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : isLoading && policies.length === 0 ? (
        <Card>
          <CardContent className="py-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin mr-2" />
            <span>Loading policies...</span>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="h-5 w-5" />
              Policies
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DataTable
              columns={columns}
              data={policies}
              loading={isLoading}
              searchKey="name"
              searchPlaceholder="Search policies..."
              pagination
              pageSize={10}
            />
          </CardContent>
        </Card>
      )}

      {detail && (
        <Card data-testid="sdn-policy-detail">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Policy {detail.id}</CardTitle>
              <Button type="button" variant="ghost" size="icon" aria-label="Close" onClick={() => setDetail(null)}>
                <X className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            {detail.loading ? (
              <span className="flex items-center text-sm">
                <Loader2 className="h-4 w-4 animate-spin mr-2" />
                Loading...
              </span>
            ) : detail.error ? (
              <p className="text-sm text-destructive">{detail.error}</p>
            ) : (
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt className="text-muted-foreground">Name</dt>
                <dd>{detail.policy?.config?.name || '-'}</dd>
                <dt className="text-muted-foreground">Description</dt>
                <dd>{detail.policy?.config?.description || '-'}</dd>
                <dt className="text-muted-foreground">Type</dt>
                <dd className="font-mono">{detail.policy?.config?.type || '-'}</dd>
                <dt className="text-muted-foreground">Status</dt>
                <dd className="font-mono">{detail.policy?.status || '-'}</dd>
                <dt className="text-muted-foreground">Priority</dt>
                <dd>{detail.policy?.config?.priority ?? '-'}</dd>
                <dt className="text-muted-foreground">Enabled</dt>
                <dd>{detail.policy?.config?.enabled ? 'yes' : 'no'}</dd>
                <dt className="text-muted-foreground">Rules</dt>
                <dd>{detail.policy?.config?.rules?.length ?? 0}</dd>
                <dt className="text-muted-foreground">Targets</dt>
                <dd>{detail.policy?.config?.targets?.length ?? 0}</dd>
                <dt className="text-muted-foreground">Hits</dt>
                <dd>{detail.policy?.hitCount ?? '0'}</dd>
                <dt className="text-muted-foreground">Bytes</dt>
                <dd>{detail.policy?.byteCount ?? '0'}</dd>
                <dt className="text-muted-foreground">Updated</dt>
                <dd>{detail.policy?.updatedAt || '-'}</dd>
              </dl>
            )}
          </CardContent>
        </Card>
      )}

      <Dialog open={applyOpen} onOpenChange={setApplyOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Apply Policy</DialogTitle>
            <DialogDescription>Apply a policy to the SDN controller, or replace one with the same ID.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="policy-id">Policy ID</Label>
              <Input
                id="policy-id"
                value={form.policyId}
                onChange={(e) => setForm((f) => ({ ...f, policyId: e.target.value }))}
                placeholder="web-acl"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-name">Name</Label>
              <Input
                id="policy-name"
                value={form.name}
                onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                placeholder="Web ACL"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-type">Type</Label>
              <select
                id="policy-type"
                className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm"
                value={form.type}
                onChange={(e) => setForm((f) => ({ ...f, type: e.target.value }))}
              >
                {POLICY_TYPES.map((t) => (
                  <option key={t} value={t}>
                    {shortName(t, 'POLICY_TYPE_')}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="policy-priority">Priority</Label>
              <Input
                id="policy-priority"
                type="number"
                value={form.priority}
                onChange={(e) => setForm((f) => ({ ...f, priority: e.target.value }))}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                id="policy-enabled"
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => setForm((f) => ({ ...f, enabled: e.target.checked }))}
              />
              <Label htmlFor="policy-enabled">Enabled</Label>
            </div>
            {applyError && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertTitle>Apply Failed</AlertTitle>
                <AlertDescription>{applyError}</AlertDescription>
              </Alert>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setApplyOpen(false)}>
              Cancel
            </Button>
            <Gated op={APPLY_POLICY}>
              <Button
                type="button"
                onClick={() => void handleApply()}
                disabled={applying || !form.policyId.trim() || !form.name.trim()}
              >
                {applying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Apply
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={deleteTarget !== null}
        onOpenChange={(open) => {
          if (!open) {
            setDeleteTarget(null);
            setDeleteError(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{deleteTarget ? `Delete policy ${policyName(deleteTarget)}?` : 'Delete policy'}</DialogTitle>
            <DialogDescription>The policy is removed from the SDN controller.</DialogDescription>
          </DialogHeader>
          {deleteError && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertTitle>Delete Failed</AlertTitle>
              <AlertDescription>{deleteError}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setDeleteTarget(null)}>
              Cancel
            </Button>
            <Gated op={DELETE_POLICY}>
              <Button type="button" variant="destructive" onClick={() => void handleDelete()} disabled={deleting}>
                {deleting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Delete
              </Button>
            </Gated>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
