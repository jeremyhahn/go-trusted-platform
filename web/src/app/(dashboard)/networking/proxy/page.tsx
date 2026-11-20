'use client';

/**
 * Reverse proxy (#2061): routes and pools of the gatewayd proxy store, the
 * merged config and its version, reload, status and the SDN zone matrix.
 * Every call goes through the SDK's ProxyService (/api/v1/proxy).
 */

import { useState } from 'react';
import { Loader2, Pencil, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { isServiceNotConfigured } from 'trusted-platform-sdk';
import type { ApiResponse } from 'trusted-platform-sdk';
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
import { Textarea } from '@/components/ui/textarea';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { ServiceUnavailableState } from '@/components/features/platform';
import { useApi, useToast } from '@/hooks';
import { formatBackends, parseBackends, useProxy } from '@/hooks/use-proxy';
import type { ProxyPool, ProxyRoute } from '@/hooks/use-proxy';

/** A route or pool in the editor; `isNew` unlocks the ID. */
interface RouteDraft {
  isNew: boolean;
  id: string;
  hosts: string;
  pathPrefix: string;
  poolId: string;
  mode: string;
}

interface PoolDraft {
  isNew: boolean;
  id: string;
  backends: string;
  balancer: string;
}

type Pending = { kind: 'route' | 'pool'; id: string } | null;

function splitList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function errMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/** Throw the server's refusal so the caller's catch reports it. */
function unwrap<T>(res: ApiResponse<T>): T | undefined {
  if (!res.success) {
    throw new Error(res.error?.message ?? 'request refused');
  }
  return res.data;
}

export default function ProxyPage() {
  const { toast } = useToast();
  const proxy = useProxy();
  const [routeDraft, setRouteDraft] = useState<RouteDraft | null>(null);
  const [poolDraft, setPoolDraft] = useState<PoolDraft | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);

  const { data: statusData, error: statusError, refetch: refetchStatus } = useApi(() => proxy.getStatus(), []);
  const {
    data: routesData,
    isLoading: routesLoading,
    error: routesError,
    refetch: refetchRoutes,
  } = useApi(() => proxy.listRoutes(), []);
  const { data: poolsData, isLoading: poolsLoading, refetch: refetchPools } = useApi(() => proxy.listPools(), []);
  const { data: configData, refetch: refetchConfig } = useApi(() => proxy.getConfig(), []);
  const { data: matrixData, error: matrixError } = useApi(() => proxy.getZoneMatrix(), []);

  const routes = routesData?.routes ?? [];
  const pools = poolsData?.pools ?? [];

  const refreshAll = () => {
    refetchStatus();
    refetchRoutes();
    refetchPools();
    refetchConfig();
  };

  const run = async (title: string, fn: () => Promise<unknown>, done: string): Promise<boolean> => {
    setBusy(true);
    try {
      await fn();
      toast({ title: done, variant: 'success' });
      refreshAll();
      return true;
    } catch (err) {
      toast({ title, description: errMessage(err), variant: 'destructive' });
      return false;
    } finally {
      setBusy(false);
    }
  };

  const reload = () =>
    run(
      'Failed to reload config',
      async () => {
        const res = unwrap(await proxy.reloadConfig());
        return res?.version;
      },
      'Config reloaded'
    );

  const openRoute = async (route?: ProxyRoute) => {
    if (!route) {
      setRouteDraft({ isNew: true, id: '', hosts: '', pathPrefix: '/', poolId: '', mode: 'mtls' });
      return;
    }
    try {
      const fresh = unwrap(await proxy.getRoute(route.id))?.route ?? route;
      setRouteDraft({
        isNew: false,
        id: fresh.id,
        hosts: (fresh.hosts ?? []).join(', '),
        pathPrefix: fresh.pathPrefix ?? '',
        poolId: fresh.poolId ?? '',
        mode: fresh.auth?.mode ?? '',
      });
    } catch (err) {
      toast({ title: 'Failed to load route', description: errMessage(err), variant: 'destructive' });
    }
  };

  const saveRoute = async () => {
    if (!routeDraft) return;
    const d = routeDraft;
    const existing = routes.find((r) => r.id === d.id);
    const route: ProxyRoute = {
      ...(existing ?? {}),
      id: d.id.trim(),
      hosts: splitList(d.hosts),
      pathPrefix: d.pathPrefix.trim(),
      poolId: d.poolId.trim(),
      auth: { ...(existing?.auth ?? {}), mode: d.mode.trim() },
    };
    const ok = await run(
      'Failed to save route',
      async () => unwrap(d.isNew ? await proxy.createRoute(route) : await proxy.updateRoute(route.id, route)),
      `Saved route ${route.id}`
    );
    if (ok) setRouteDraft(null);
  };

  const openPool = async (pool?: ProxyPool) => {
    if (!pool) {
      setPoolDraft({ isNew: true, id: '', backends: '', balancer: '' });
      return;
    }
    try {
      const fresh = unwrap(await proxy.getPool(pool.id))?.pool ?? pool;
      setPoolDraft({
        isNew: false,
        id: fresh.id,
        backends: formatBackends(fresh.backends),
        balancer: fresh.balancer ?? '',
      });
    } catch (err) {
      toast({ title: 'Failed to load pool', description: errMessage(err), variant: 'destructive' });
    }
  };

  const savePool = async () => {
    if (!poolDraft) return;
    const d = poolDraft;
    const existing = pools.find((p) => p.id === d.id);
    const pool: ProxyPool = {
      ...(existing ?? {}),
      id: d.id.trim(),
      backends: parseBackends(d.backends),
      balancer: d.balancer.trim(),
    };
    const ok = await run(
      'Failed to save pool',
      async () => unwrap(d.isNew ? await proxy.createPool(pool) : await proxy.updatePool(pool.id, pool)),
      `Saved pool ${pool.id}`
    );
    if (ok) setPoolDraft(null);
  };

  const confirmDelete = async () => {
    if (!pendingDelete) return;
    const { kind, id } = pendingDelete;
    const ok = await run(
      `Failed to delete ${kind}`,
      async () => unwrap(kind === 'route' ? await proxy.deleteRoute(id) : await proxy.deletePool(id)),
      `Deleted ${kind} ${id}`
    );
    if (ok) setPendingDelete(null);
  };

  if (isServiceNotConfigured(routesError) || isServiceNotConfigured(statusError)) {
    return (
      <div className="p-6">
        <ServiceUnavailableState
          service="Reverse proxy"
          description="This node serves no proxy route store. Point the console at the control-plane node."
        />
      </div>
    );
  }

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Reverse proxy</h1>
          <p className="text-sm text-muted-foreground">
            Routes and backend pools every syncing gatewayd forwards with.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={refreshAll} disabled={busy}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button onClick={reload} disabled={busy}>
            {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
            Reload config
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Status</CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
          <div>
            <div className="text-muted-foreground">Config version</div>
            <div data-testid="proxy-status-version">{String(statusData?.version ?? '0')}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Routes</div>
            <div data-testid="proxy-status-routes">{String(statusData?.routeCount ?? 0)}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Pools</div>
            <div data-testid="proxy-status-pools">{String(statusData?.poolCount ?? 0)}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Last update</div>
            <div data-testid="proxy-status-updated">
              {statusData?.updatedAt && statusData.updatedAt !== '0'
                ? new Date(Number(statusData.updatedAt) * 1000).toISOString()
                : 'never'}
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="routes">
        <TabsList>
          <TabsTrigger value="routes">Routes</TabsTrigger>
          <TabsTrigger value="pools">Pools</TabsTrigger>
          <TabsTrigger value="config">Config</TabsTrigger>
          <TabsTrigger value="zones">Zone matrix</TabsTrigger>
        </TabsList>

        <TabsContent value="routes" className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={() => openRoute()}>
              <Plus className="mr-2 h-4 w-4" />
              Add route
            </Button>
          </div>
          {routesError && !routesLoading ? (
            <Alert variant="destructive">
              <AlertTitle>Failed to load routes</AlertTitle>
              <AlertDescription>{errMessage(routesError)}</AlertDescription>
            </Alert>
          ) : null}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Hosts</TableHead>
                <TableHead>Path prefix</TableHead>
                <TableHead>Pool</TableHead>
                <TableHead>Auth</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {routes.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="font-mono">{r.id}</TableCell>
                  <TableCell>{(r.hosts ?? []).join(', ') || '*'}</TableCell>
                  <TableCell className="font-mono">{r.pathPrefix}</TableCell>
                  <TableCell>{r.poolId}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{r.auth?.mode || 'default'}</Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" aria-label="Edit" onClick={() => openRoute(r)}>
                      <Pencil className="h-4 w-4" />
                      <span className="sr-only">Edit</span>
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label="Delete"
                      onClick={() => setPendingDelete({ kind: 'route', id: r.id })}
                    >
                      <Trash2 className="h-4 w-4" />
                      <span className="sr-only">Delete</span>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {routes.length === 0 && !routesLoading ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No routes
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TabsContent>

        <TabsContent value="pools" className="space-y-4">
          <div className="flex justify-end">
            <Button onClick={() => openPool()}>
              <Plus className="mr-2 h-4 w-4" />
              Add pool
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Backends</TableHead>
                <TableHead>Balancer</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pools.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-mono">{p.id}</TableCell>
                  <TableCell className="font-mono">{(p.backends ?? []).map((b) => b.url).join(', ')}</TableCell>
                  <TableCell>{p.balancer || 'round-robin'}</TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" aria-label="Edit" onClick={() => openPool(p)}>
                      <Pencil className="h-4 w-4" />
                      <span className="sr-only">Edit</span>
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      aria-label="Delete"
                      onClick={() => setPendingDelete({ kind: 'pool', id: p.id })}
                    >
                      <Trash2 className="h-4 w-4" />
                      <span className="sr-only">Delete</span>
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
              {pools.length === 0 && !poolsLoading ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-center text-muted-foreground">
                    No pools
                  </TableCell>
                </TableRow>
              ) : null}
            </TableBody>
          </Table>
        </TabsContent>

        <TabsContent value="config">
          <Card>
            <CardHeader>
              <CardTitle data-testid="proxy-config-version">
                Merged config, version {String(configData?.version ?? '0')}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="max-h-[480px] overflow-auto rounded bg-muted p-4 text-xs">
                {JSON.stringify({ routes: configData?.routes ?? [], pools: configData?.pools ?? [] }, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="zones">
          {matrixError ? (
            <Alert variant="destructive" data-testid="proxy-zone-matrix-error">
              <AlertTitle>Zone matrix unavailable</AlertTitle>
              <AlertDescription>{errMessage(matrixError)}</AlertDescription>
            </Alert>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Zones</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex flex-wrap gap-2" data-testid="proxy-zones">
                  {(matrixData?.zones ?? []).map((z) => (
                    <Badge key={z} variant="secondary">
                      {z}
                    </Badge>
                  ))}
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>From</TableHead>
                      <TableHead>To</TableHead>
                      <TableHead>Services</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {(matrixData?.pairs ?? []).map((p) => (
                      <TableRow key={`${p.from}->${p.to}`}>
                        <TableCell>{p.from}</TableCell>
                        <TableCell>{p.to}</TableCell>
                        <TableCell>{(p.services ?? []).join(', ') || 'all'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      <Dialog open={routeDraft !== null} onOpenChange={(open) => !open && setRouteDraft(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{routeDraft?.isNew ? 'Add route' : `Edit route ${routeDraft?.id ?? ''}`}</DialogTitle>
            <DialogDescription>Hosts are exact names or *; empty matches any host.</DialogDescription>
          </DialogHeader>
          {routeDraft ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="proxy-route-id">Route ID</Label>
                <Input
                  id="proxy-route-id"
                  value={routeDraft.id}
                  disabled={!routeDraft.isNew}
                  onChange={(e) => setRouteDraft({ ...routeDraft, id: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-route-hosts">Hosts</Label>
                <Input
                  id="proxy-route-hosts"
                  value={routeDraft.hosts}
                  onChange={(e) => setRouteDraft({ ...routeDraft, hosts: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-route-prefix">Path prefix</Label>
                <Input
                  id="proxy-route-prefix"
                  value={routeDraft.pathPrefix}
                  onChange={(e) => setRouteDraft({ ...routeDraft, pathPrefix: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-route-pool">Pool</Label>
                <Input
                  id="proxy-route-pool"
                  list="proxy-pool-ids"
                  value={routeDraft.poolId}
                  onChange={(e) => setRouteDraft({ ...routeDraft, poolId: e.target.value })}
                />
                <datalist id="proxy-pool-ids">
                  {pools.map((p) => (
                    <option key={p.id} value={p.id} />
                  ))}
                </datalist>
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-route-mode">Auth mode</Label>
                <Input
                  id="proxy-route-mode"
                  placeholder="public | mtls | token | mtls-or-token"
                  value={routeDraft.mode}
                  onChange={(e) => setRouteDraft({ ...routeDraft, mode: e.target.value })}
                />
              </div>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setRouteDraft(null)}>
              Cancel
            </Button>
            <Button onClick={saveRoute} disabled={busy || !routeDraft?.id.trim()}>
              Save route
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={poolDraft !== null} onOpenChange={(open) => !open && setPoolDraft(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{poolDraft?.isNew ? 'Add pool' : `Edit pool ${poolDraft?.id ?? ''}`}</DialogTitle>
            <DialogDescription>One backend URL per line; add =weight to weight it.</DialogDescription>
          </DialogHeader>
          {poolDraft ? (
            <div className="space-y-3">
              <div className="space-y-1">
                <Label htmlFor="proxy-pool-id">Pool ID</Label>
                <Input
                  id="proxy-pool-id"
                  value={poolDraft.id}
                  disabled={!poolDraft.isNew}
                  onChange={(e) => setPoolDraft({ ...poolDraft, id: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-pool-backends">Backends</Label>
                <Textarea
                  id="proxy-pool-backends"
                  value={poolDraft.backends}
                  onChange={(e) => setPoolDraft({ ...poolDraft, backends: e.target.value })}
                />
              </div>
              <div className="space-y-1">
                <Label htmlFor="proxy-pool-balancer">Balancer</Label>
                <Input
                  id="proxy-pool-balancer"
                  placeholder="round-robin"
                  value={poolDraft.balancer}
                  onChange={(e) => setPoolDraft({ ...poolDraft, balancer: e.target.value })}
                />
              </div>
            </div>
          ) : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => setPoolDraft(null)}>
              Cancel
            </Button>
            <Button onClick={savePool} disabled={busy || !poolDraft?.id.trim()}>
              Save pool
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Delete {pendingDelete?.kind} {pendingDelete?.id}?
            </DialogTitle>
            <DialogDescription>
              Syncing gateways stop using it at the next config version. A pool a route still uses is refused.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingDelete(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirmDelete} disabled={busy}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
