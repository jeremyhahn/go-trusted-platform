'use client';

/**
 * TenantDirectoryCard lists the tenants and runs the TenantService lifecycle
 * ops through the SDK: create, rename (UpdateTenant), delete behind a confirm,
 * suspend, resume, find by name and sync. Each control sits in the capability
 * gate on its route; the list read is withheld, with the server's reason, when
 * its op is not offered (#2067).
 */

import { useCallback, useEffect, useState } from 'react';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useTenant } from '@/hooks';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';

interface ActionResult {
  success: boolean;
  error?: { message?: string };
}

interface TenantRow {
  id: string;
  name: string;
  displayName?: string;
  state?: string;
}

const SUSPENDED = 'TENANT_STATE_SUSPENDED';

export function TenantDirectoryCard({ pageSize = 50 }: { pageSize?: number } = {}) {
  const tenants = useTenant();
  const { toast } = useToast();
  const listCap = useCapabilities().capability('GET /api/v1/tenants');
  const [rows, setRows] = useState<TenantRow[]>([]);
  const [offset, setOffset] = useState(0);
  const [total, setTotal] = useState(0);
  const [newName, setNewName] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState('');
  const [confirmDelete, setConfirmDelete] = useState<TenantRow | null>(null);
  const [lookupName, setLookupName] = useState('');
  const [lookup, setLookup] = useState<TenantRow | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!listCap.enabled) {
      return;
    }
    try {
      // One page at a time: the server answers the page and the total.
      const res = await tenants.listTenants({ limit: pageSize, offset });
      if (res.success) {
        const page = (res.data?.tenants ?? []) as TenantRow[];
        const count = Number(res.data?.total ?? 0);
        if (page.length === 0 && offset > 0 && count > 0) {
          // The last tenant on this page went away: step back a page.
          setOffset(Math.max(0, offset - pageSize));
          return;
        }
        setRows(page);
        setTotal(count);
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    }
  }, [tenants, listCap.enabled, pageSize, offset]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (action: () => Promise<ActionResult>, onSuccess?: () => void, reload = true) => {
    setBusy(true);
    setError(null);
    let succeeded = false;
    try {
      const res = await action();
      if (res.success) {
        succeeded = true;
        onSuccess?.();
      } else {
        setError(res.error?.message ?? 'request failed');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'request failed');
    } finally {
      setBusy(false);
    }
    if (succeeded && reload) {
      await load();
    }
  };

  const find = () =>
    run(
      async () => {
        setLookup(null);
        const res = await tenants.getTenantByName(lookupName.trim());
        if (res.success) {
          setLookup((res.data?.tenant ?? null) as TenantRow | null);
        }
        return res;
      },
      undefined,
      false
    );

  return (
    <Card>
      <CardHeader>
        <CardTitle>Tenants</CardTitle>
        <CardDescription>Every tenant: create, rename, suspend, resume, delete, find by name and sync.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="tenant-directory-new-name">Tenant name</Label>
            <Input id="tenant-directory-new-name" value={newName} onChange={(e) => setNewName(e.target.value)} />
          </div>
          <Gated op="POST /api/v1/tenants">
            <Button
              disabled={busy || newName.trim() === ''}
              onClick={() => run(() => tenants.createTenant({ name: newName.trim() }), () => setNewName(''))}
            >
              Create tenant
            </Button>
          </Gated>
          <Gated op="POST /api/v1/tenants/sync">
            <Button
              variant="outline"
              disabled={busy}
              onClick={() =>
                run(
                  () => tenants.syncTenants(),
                  () => toast({ title: 'Tenants synced', description: 'The tenant directory was synced.' })
                )
              }
            >
              Sync
            </Button>
          </Gated>
        </div>

        <div className="flex flex-wrap items-end gap-4">
          <div className="space-y-1">
            <Label htmlFor="tenant-directory-lookup">Find by name</Label>
            <Input id="tenant-directory-lookup" value={lookupName} onChange={(e) => setLookupName(e.target.value)} />
          </div>
          <Gated op="GET /api/v1/tenants/by-name/{name}">
            <Button variant="outline" disabled={busy || lookupName.trim() === ''} onClick={() => find()}>
              Find
            </Button>
          </Gated>
        </div>
        {lookup && (
          <div data-testid="tenant-lookup-result" className="flex flex-wrap gap-4 text-sm">
            <span className="font-mono">{lookup.id}</span>
            <span>{lookup.name}</span>
            {lookup.displayName && <span>{lookup.displayName}</span>}
            <span>{lookup.state}</span>
          </div>
        )}

        {!listCap.enabled ? (
          <p className="text-sm text-muted-foreground">{listCap.reason}</p>
        ) : (
          <div className="space-y-2">
          <ul data-testid="tenant-directory-list" className="divide-y">
            {rows.map((t) => (
              <li key={t.id} data-testid={`tenant-row-${t.id}`} className="flex flex-wrap items-end gap-4 py-2 text-sm">
                <span className="font-mono">{t.id}</span>
                <span>{t.name}</span>
                {t.displayName && <span>{t.displayName}</span>}
                <span>{t.state}</span>
                {editing === t.id ? (
                  <>
                    <div className="space-y-1">
                      <Label htmlFor={`tenant-directory-display-${t.id}`}>Display name</Label>
                      <Input
                        id={`tenant-directory-display-${t.id}`}
                        value={displayName}
                        onChange={(e) => setDisplayName(e.target.value)}
                      />
                    </div>
                    <Gated op="PUT /api/v1/tenants/{id}">
                      <Button
                        size="sm"
                        disabled={busy}
                        onClick={() =>
                          run(() => tenants.updateTenant({ tenantId: t.id, displayName }), () => setEditing(null))
                        }
                      >
                        Save
                      </Button>
                    </Gated>
                    <Button size="sm" variant="ghost" onClick={() => setEditing(null)}>
                      Cancel
                    </Button>
                  </>
                ) : (
                  <Gated op="PUT /api/v1/tenants/{id}">
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => {
                        setEditing(t.id);
                        setDisplayName(t.displayName ?? '');
                      }}
                    >
                      Edit
                    </Button>
                  </Gated>
                )}
                {t.state === SUSPENDED ? (
                  <Gated op="POST /api/v1/tenants/{id}/resume">
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => run(() => tenants.resumeTenant(t.id))}>
                      Resume
                    </Button>
                  </Gated>
                ) : (
                  <Gated op="POST /api/v1/tenants/{id}/suspend">
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => run(() => tenants.suspendTenant(t.id))}>
                      Suspend
                    </Button>
                  </Gated>
                )}
                <Gated op="DELETE /api/v1/tenants/{id}">
                  <Button size="sm" variant="destructive" disabled={busy} onClick={() => setConfirmDelete(t)}>
                    Delete
                  </Button>
                </Gated>
              </li>
            ))}
          </ul>
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <span data-testid="tenant-directory-total">
              {rows.length === 0 ? 0 : offset + 1}–{offset + rows.length} of {total}
            </span>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || offset === 0}
              onClick={() => setOffset(Math.max(0, offset - pageSize))}
            >
              Previous page
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={busy || offset + pageSize >= total}
              onClick={() => setOffset(offset + pageSize)}
            >
              Next page
            </Button>
          </div>
          </div>
        )}

        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}

        <Dialog open={confirmDelete !== null} onOpenChange={(open) => !open && setConfirmDelete(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete tenant {confirmDelete?.name}?</DialogTitle>
              <DialogDescription>The tenant and its identity records are removed. This cannot be undone.</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button variant="outline" onClick={() => setConfirmDelete(null)}>
                Cancel
              </Button>
              <Gated op="DELETE /api/v1/tenants/{id}">
                <Button
                  variant="destructive"
                  disabled={busy}
                  onClick={() => {
                    const target = confirmDelete;
                    setConfirmDelete(null);
                    if (target) {
                      void run(() => tenants.deleteTenant(target.id));
                    }
                  }}
                >
                  Delete
                </Button>
              </Gated>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
