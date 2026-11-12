"use client";

/**
 * IAM tenants: list, create, view, update and delete (#1744).
 * Routes: GET/POST /tenants, GET/PUT/DELETE /tenants/{tenant}.
 */

import React, { useState } from "react";
import { AlertCircle, Building2, Loader2, Plus, Trash2 } from "lucide-react";
import type { IAMTenant } from "trusted-platform-sdk";
import { useIAMTenants, useToast } from "@/hooks";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : "Unknown error";
}

// The REST reply may carry the tenant bare or under a "tenant" key (#445).
function unwrapTenant(data: unknown): IAMTenant | null {
  if (!data || typeof data !== "object") return null;
  const wrapped = data as { tenant?: IAMTenant };
  return wrapped.tenant ?? (data as IAMTenant);
}

export default function TenantsPage() {
  const { tenants, isLoading, error, refetch, getTenant, createTenant, updateTenant, deleteTenant } =
    useIAMTenants();
  const { toast } = useToast();

  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<IAMTenant | null>(null);
  const [editName, setEditName] = useState("");
  const [pendingDelete, setPendingDelete] = useState<IAMTenant | null>(null);

  const run = async (label: string, fn: () => Promise<void>) => {
    setBusy(true);
    try {
      await fn();
    } catch (err) {
      toast({ title: `Failed to ${label}`, description: errorMessage(err), variant: "destructive" });
    } finally {
      setBusy(false);
    }
  };

  const onCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newName.trim()) return;
    void run("create tenant", async () => {
      await createTenant({ name: newName.trim(), ...(newId.trim() ? { id: newId.trim() } : {}) });
      toast({ title: "Tenant created", variant: "success" });
      setNewId("");
      setNewName("");
      refetch();
    });
  };

  const onView = (tenantId: string) => {
    void run("load tenant", async () => {
      const res = await getTenant(tenantId);
      const t = unwrapTenant(res.data);
      setSelected(t);
      setEditName(t?.name ?? "");
    });
  };

  const onUpdate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selected) return;
    void run("update tenant", async () => {
      const res = await updateTenant({ tenantId: selected.id, name: editName.trim() });
      setSelected(unwrapTenant(res.data) ?? { ...selected, name: editName.trim() });
      toast({ title: "Tenant updated", variant: "success" });
      refetch();
    });
  };

  const onConfirmDelete = () => {
    const target = pendingDelete;
    if (!target) return;
    void run("delete tenant", async () => {
      await deleteTenant(target.id);
      toast({ title: "Tenant deleted", variant: "success" });
      setPendingDelete(null);
      if (selected?.id === target.id) setSelected(null);
      refetch();
    });
  };

  return (
    <div className="container mx-auto py-6 space-y-6">
      <div className="space-y-1">
        <h1 className="text-3xl font-bold tracking-tight">Tenants</h1>
        <p className="text-muted-foreground">Create, inspect, rename and delete IAM tenants</p>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertTitle>Error Loading Tenants</AlertTitle>
          <AlertDescription>{errorMessage(error)}</AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Create tenant</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onCreate} className="grid gap-4 md:grid-cols-3 items-end">
            <div className="space-y-2">
              <Label htmlFor="tenant-new-id">Tenant ID (optional)</Label>
              <Input id="tenant-new-id" value={newId} onChange={(e) => setNewId(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="tenant-new-name">Tenant name</Label>
              <Input id="tenant-new-name" value={newName} onChange={(e) => setNewName(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy || !newName.trim()}>
              <Plus className="h-4 w-4 mr-2" /> Create tenant
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>All tenants</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-5 w-5 animate-spin" />
              <span>Loading tenants…</span>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tenants.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={3}>No tenants.</TableCell>
                  </TableRow>
                ) : (
                  tenants.map((t) => (
                    <TableRow key={t.id}>
                      <TableCell className="font-medium">
                        <Building2 className="inline h-4 w-4 mr-2 text-muted-foreground" />
                        {t.name || t.id}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{t.id}</TableCell>
                      <TableCell className="text-right space-x-2">
                        <Button
                          size="sm"
                          variant="outline"
                          aria-label={`View tenant ${t.id}`}
                          onClick={() => onView(t.id)}
                        >
                          View
                        </Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          aria-label={`Delete tenant ${t.id}`}
                          onClick={() => setPendingDelete(t)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {selected && (
        <Card data-testid="tenant-detail">
          <CardHeader>
            <CardTitle>{selected.name || selected.id}</CardTitle>
            <CardDescription className="font-mono text-xs">{selected.id}</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={onUpdate} className="flex items-end gap-4">
              <div className="space-y-2 flex-1">
                <Label htmlFor="tenant-edit-name">New name</Label>
                <Input
                  id="tenant-edit-name"
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                />
              </div>
              <Button type="submit" disabled={busy || !editName.trim()}>
                Save tenant
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Dialog open={pendingDelete !== null} onOpenChange={(open) => !open && setPendingDelete(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete tenant?</DialogTitle>
            <DialogDescription>
              This deletes tenant &quot;{pendingDelete?.name || pendingDelete?.id}&quot; and cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPendingDelete(null)}>
              Cancel
            </Button>
            <Button variant="destructive" disabled={busy} onClick={onConfirmDelete}>
              Delete tenant
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
