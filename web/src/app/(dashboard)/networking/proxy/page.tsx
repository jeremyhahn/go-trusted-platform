"use client";

import * as React from "react";
import { Pencil, Plus, RefreshCw, RotateCw, Trash2 } from "lucide-react";
import type { ApiResponse, ProxyRoute } from "trusted-platform-sdk";
import { PageHeader } from "@/components/layout/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useApi, useToast } from "@/hooks";
import { proxyRouteMatch, useProxy } from "@/hooks/use-proxy";
import {
  ProxyRouteDialog,
  proxyRouteFromForm,
  proxyRouteToForm,
  type ProxyRouteFormValues,
} from "./proxy-route-dialog";

const EMPTY_FORM: ProxyRouteFormValues = { id: "", hosts: "", pathPrefix: "", poolId: "" };

type Editor =
  | { mode: "create"; initial: ProxyRouteFormValues }
  | { mode: "edit"; id: string; base: ProxyRoute; initial: ProxyRouteFormValues };

function formatUpdated(updatedAt: string | undefined): string {
  const secs = Number(updatedAt);
  if (!updatedAt || !Number.isFinite(secs) || secs === 0) return "-";
  return new Date(secs * 1000).toISOString();
}

/**
 * Proxy routes page: the reverse-proxy routes and configuration status on
 * `/api/v1/proxy`, through ListRoutes, GetRoute, CreateRoute, UpdateRoute,
 * DeleteRoute, GetProxyStatus and ReloadProxyConfig on `client.proxy`.
 */
export default function ProxyRoutesPage() {
  const proxy = useProxy();
  const { toast } = useToast();
  const status = useApi(() => proxy.getStatus(), [proxy]);
  const routes = useApi(() => proxy.listRoutes(), [proxy]);

  const [editor, setEditor] = React.useState<Editor | null>(null);
  const [pendingDelete, setPendingDelete] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);

  const refresh = React.useCallback(() => {
    void routes.refetch();
    void status.refetch();
  }, [routes, status]);

  /** Runs a write; on success toasts title, closes the dialogs and re-reads. */
  const write = async (
    title: string,
    call: () => Promise<ApiResponse<{ version?: string }>>,
  ): Promise<void> => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success === false) {
        toast({
          title: "Proxy request failed",
          description: res.error?.message,
          variant: "destructive",
        });
        return;
      }
      toast({ title, description: `version ${res.data?.version ?? ""}` });
      setEditor(null);
      setPendingDelete(null);
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const onEdit = async (id: string) => {
    const res = await proxy.getRoute(id);
    if (res.success === false || !res.data?.route) {
      toast({
        title: "Proxy request failed",
        description: res.error?.message,
        variant: "destructive",
      });
      return;
    }
    const route = res.data.route;
    setEditor({ mode: "edit", id, base: route, initial: proxyRouteToForm(route) });
  };

  const onSave = (values: ProxyRouteFormValues) => {
    if (!editor) return;
    if (editor.mode === "create") {
      void write("Route created", () => proxy.createRoute(proxyRouteFromForm(values)));
    } else {
      const { id, base } = editor;
      void write("Route updated", () => proxy.updateRoute(id, proxyRouteFromForm(values, base)));
    }
  };

  const list = routes.data?.routes ?? [];

  return (
    <div className="container mx-auto py-6 space-y-6">
      <PageHeader
        title="Proxy routes"
        description="Reverse-proxy routes and configuration status"
      >
        <Button variant="outline" size="sm" onClick={refresh} disabled={routes.isFetching}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void write("Config reloaded", () => proxy.reloadConfig())}
          disabled={busy}
        >
          <RotateCw className="h-4 w-4 mr-2" />
          Reload config
        </Button>
        <Button size="sm" onClick={() => setEditor({ mode: "create", initial: EMPTY_FORM })}>
          <Plus className="h-4 w-4 mr-2" />
          New route
        </Button>
      </PageHeader>

      <Card data-testid="proxy-status">
        <CardHeader>
          <CardTitle>Status</CardTitle>
        </CardHeader>
        <CardContent>
          {status.error ? (
            <p role="alert" className="text-sm text-destructive">
              {status.error.message}
            </p>
          ) : status.data ? (
            <dl className="grid grid-cols-2 gap-2 text-sm max-w-md">
              <dt className="text-muted-foreground">Version</dt>
              <dd className="font-mono">{status.data.version || "-"}</dd>
              <dt className="text-muted-foreground">Routes</dt>
              <dd>{status.data.routeCount ?? 0}</dd>
              <dt className="text-muted-foreground">Pools</dt>
              <dd>{status.data.poolCount ?? 0}</dd>
              <dt className="text-muted-foreground">Updated</dt>
              <dd className="font-mono">{formatUpdated(status.data.updatedAt)}</dd>
            </dl>
          ) : null}
        </CardContent>
      </Card>

      <Card data-testid="proxy-routes">
        <CardHeader>
          <CardTitle>Routes</CardTitle>
        </CardHeader>
        <CardContent>
          {routes.error ? (
            <p role="alert" className="text-sm text-destructive">
              {routes.error.message}
            </p>
          ) : !routes.data ? null : list.length === 0 ? (
            <p className="text-sm text-muted-foreground py-8 text-center">
              No routes configured.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead>Pool</TableHead>
                  <TableHead>Auth</TableHead>
                  <TableHead className="w-24" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {list.map((r) => {
                  const id = r.id ?? "";
                  return (
                    <TableRow key={id}>
                      <TableCell className="font-mono">{id}</TableCell>
                      <TableCell>{proxyRouteMatch(r)}</TableCell>
                      <TableCell className="font-mono">{r.poolId}</TableCell>
                      <TableCell>{r.auth?.mode || "-"}</TableCell>
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Edit ${id}`}
                          onClick={() => void onEdit(id)}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete ${id}`}
                          onClick={() => setPendingDelete(id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ProxyRouteDialog
        open={editor !== null}
        mode={editor?.mode ?? "create"}
        initial={editor?.initial ?? EMPTY_FORM}
        saving={busy}
        onCancel={() => setEditor(null)}
        onSave={onSave}
      />

      <Dialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open && !busy) setPendingDelete(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete route</DialogTitle>
            <DialogDescription>
              Delete route {pendingDelete}? Traffic it matches will no longer be proxied.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingDelete(null)} disabled={busy}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={busy}
              onClick={() => {
                const id = pendingDelete;
                if (id !== null) void write("Route deleted", () => proxy.deleteRoute(id));
              }}
            >
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
