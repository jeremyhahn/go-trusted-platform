"use client";

import * as React from "react";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";
import type { ApiResponse, ProxyPool } from "trusted-platform-sdk";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useApi, useToast } from "@/hooks";
import { proxyPoolSummary, useProxy } from "@/hooks/use-proxy";
import {
  ProxyPoolDialog,
  proxyPoolFromForm,
  proxyPoolToForm,
  type ProxyPoolFormValues,
} from "./proxy-pool-dialog";

const EMPTY_FORM: ProxyPoolFormValues = { id: "", backends: "", balancer: "" };

interface Editing {
  mode: "create" | "edit";
  initial: ProxyPoolFormValues;
  base?: ProxyPool;
}

/**
 * Proxy pools page: the ProxyService operations ListPools, GetPool,
 * CreatePool, UpdatePool and DeletePool on the backend pools, the merged
 * configuration (GetProxyConfig) and the SDN zone matrix (GetZoneMatrix),
 * all through `client.proxy`.
 */
export default function ProxyPoolsPage() {
  const proxy = useProxy();
  const { toast } = useToast();
  const pools = useApi(() => proxy.listPools(), [proxy]);
  const config = useApi(() => proxy.getConfig(), [proxy]);
  const matrix = useApi(() => proxy.getZoneMatrix(), [proxy]);

  const [editing, setEditing] = React.useState<Editing | null>(null);
  const [deleting, setDeleting] = React.useState<string | null>(null);
  const [saving, setSaving] = React.useState(false);

  const refused = (res: ApiResponse<unknown>) => {
    toast({ title: "Proxy request failed", description: res.error?.message, variant: "destructive" });
  };

  const write = async (
    send: () => Promise<ApiResponse<{ version?: string }>>,
    title: string,
    close: () => void
  ) => {
    setSaving(true);
    try {
      const res = await send();
      if (res.success === false) {
        refused(res);
        return;
      }
      toast({ title, description: `version ${res.data?.version ?? ""}` });
      close();
      void pools.refetch();
      void config.refetch();
    } finally {
      setSaving(false);
    }
  };

  const onEdit = async (id: string) => {
    const res = await proxy.getPool(id);
    if (res.success === false || !res.data?.pool) {
      refused(res);
      return;
    }
    const pool = res.data.pool;
    setEditing({ mode: "edit", initial: proxyPoolToForm(pool), base: pool });
  };

  const onSave = (values: ProxyPoolFormValues) => {
    if (!editing) return;
    if (editing.mode === "create") {
      void write(() => proxy.createPool(proxyPoolFromForm(values)), "Pool created", () => setEditing(null));
    } else {
      const id = editing.initial.id;
      void write(
        () => proxy.updatePool(id, proxyPoolFromForm(values, editing.base)),
        "Pool updated",
        () => setEditing(null)
      );
    }
  };

  const onConfirmDelete = () => {
    if (!deleting) return;
    const id = deleting;
    void write(() => proxy.deletePool(id), "Pool deleted", () => setDeleting(null));
  };

  const poolList = pools.data?.pools ?? [];
  const pairs = matrix.data?.pairs ?? [];

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader title="Proxy pools" description="Backend pools, merged configuration and the zone matrix">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void pools.refetch();
            void config.refetch();
            void matrix.refetch();
          }}
        >
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
        <Button size="sm" onClick={() => setEditing({ mode: "create", initial: EMPTY_FORM })}>
          <Plus className="h-4 w-4 mr-2" />
          New pool
        </Button>
      </PageHeader>

      <Card data-testid="proxy-pools">
        <CardHeader>
          <CardTitle>Pools</CardTitle>
        </CardHeader>
        <CardContent>
          {pools.error ? (
            <p role="alert" className="text-sm text-destructive">
              {pools.error.message}
            </p>
          ) : pools.isLoading ? null : poolList.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">No pools configured.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Backends</TableHead>
                  <TableHead>TLS</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {poolList.map((p) => (
                  <TableRow key={p.id}>
                    <TableCell className="font-mono">{p.id}</TableCell>
                    <TableCell>{proxyPoolSummary(p)}</TableCell>
                    <TableCell>{p.tls?.trustClass || "-"}</TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Edit ${p.id}`}
                        onClick={() => void onEdit(p.id ?? "")}
                      >
                        <Pencil className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={`Delete ${p.id}`}
                        onClick={() => setDeleting(p.id ?? "")}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card data-testid="proxy-config">
        <CardHeader>
          <CardTitle>Merged configuration</CardTitle>
        </CardHeader>
        <CardContent>
          {config.error ? (
            <p role="alert" className="text-sm text-destructive">
              {config.error.message}
            </p>
          ) : (
            <dl className="grid grid-cols-2 gap-2 text-sm max-w-md">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono">{config.data?.version ?? "-"}</dd>
              <dt className="text-muted-foreground">Routes</dt>
              <dd>{config.data?.routes?.length ?? 0}</dd>
              <dt className="text-muted-foreground">Pools</dt>
              <dd>{config.data?.pools?.length ?? 0}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      <Card data-testid="proxy-zone-matrix">
        <CardHeader>
          <CardTitle>Zone matrix</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {matrix.error ? (
            <p role="alert" className="text-sm text-destructive">
              {matrix.error.message}
            </p>
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                {(matrix.data?.zones ?? []).map((z) => (
                  <Badge key={z} variant="secondary">
                    {z}
                  </Badge>
                ))}
              </div>
              {pairs.length === 0 ? (
                <p className="text-sm text-muted-foreground">No zone pairs allowed.</p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>From</TableHead>
                      <TableHead>To</TableHead>
                      <TableHead>Services</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {pairs.map((pair, i) => (
                      <TableRow key={`${pair.from}-${pair.to}-${i}`}>
                        <TableCell>{pair.from}</TableCell>
                        <TableCell>{pair.to}</TableCell>
                        <TableCell>{pair.services?.length ? pair.services.join(", ") : "all"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <ProxyPoolDialog
        open={editing !== null}
        mode={editing?.mode ?? "create"}
        initial={editing?.initial ?? EMPTY_FORM}
        saving={saving}
        onCancel={() => setEditing(null)}
        onSave={onSave}
      />

      <Dialog
        open={deleting !== null}
        onOpenChange={(open) => {
          if (!open && !saving) setDeleting(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete pool</DialogTitle>
            <DialogDescription>
              Delete pool {deleting}? Routes that use it will fail until they point at another pool.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleting(null)} disabled={saving}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onConfirmDelete} disabled={saving}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
