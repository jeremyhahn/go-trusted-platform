"use client";

/**
 * Tenant lifecycle page (#1758).
 *
 * Look a tenant up by name, edit it, suspend, resume or delete it, set its
 * compute quotas, check a quota, sync tenants, and read or rotate the
 * tenant DEK. Delete, suspend and DEK rotation sit behind a confirm dialog.
 * Uses the trusted-platform-sdk TenantService through useTenantLifecycle.
 */
import * as React from "react";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useTenantLifecycle } from "@/hooks";

type ConfirmAction = "delete" | "suspend" | "rotate";

const CONFIRM_TEXT: Record<ConfirmAction, { title: string; description: string; label: string }> = {
  delete: {
    title: "Delete tenant",
    description: "The tenant and everything it owns are removed. This cannot be undone.",
    label: "Delete",
  },
  suspend: {
    title: "Suspend tenant",
    description: "Members of the tenant lose access until it is resumed.",
    label: "Suspend",
  },
  rotate: {
    title: "Rotate tenant DEK",
    description: "A new data encryption key version is created and becomes the active version. Existing data is not re-encrypted by this action.",
    label: "Rotate",
  },
};

export default function TenantLifecyclePage() {
  const lifecycle = useTenantLifecycle();
  const { tenant, dekStatus, quotaCheck, busy, error, notice } = lifecycle;

  const [name, setName] = React.useState("");
  // null until edited, so the field shows the loaded tenant's display name.
  const [editedName, setDisplayName] = React.useState<string | null>(null);
  const displayName = editedName ?? tenant?.displayName ?? "";
  const [maxVms, setMaxVms] = React.useState("");
  const [resource, setResource] = React.useState("vms");
  const [amount, setAmount] = React.useState("1");
  const [confirm, setConfirm] = React.useState<ConfirmAction | null>(null);

  const onConfirm = async () => {
    const action = confirm;
    setConfirm(null);
    if (action === "delete") await lifecycle.remove();
    if (action === "suspend") await lifecycle.suspend();
    if (action === "rotate") await lifecycle.rotateDEK();
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Tenant Lifecycle"
        description="Look up, edit, suspend, resume or delete a tenant, and manage its quotas and DEK"
        actions={
          <Button variant="outline" onClick={() => lifecycle.sync()} disabled={busy}>
            Sync tenants
          </Button>
        }
      />

      {error && (
        <div role="alert" className="rounded-md border border-destructive p-3 text-sm text-destructive">
          {error}
        </div>
      )}
      {notice && (
        <div role="status" className="rounded-md border p-3 text-sm">
          {notice}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Find tenant</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (!name.trim()) return;
              setDisplayName(null);
              void lifecycle.lookup(name.trim());
            }}
          >
            <div className="flex-1 space-y-1">
              <Label htmlFor="tenant-name">Tenant name</Label>
              <Input id="tenant-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <Button type="submit" disabled={busy || !name.trim()}>
              Look up
            </Button>
          </form>
        </CardContent>
      </Card>

      {tenant && (
        <>
          <Card data-testid="tenant-details">
            <CardHeader>
              <CardTitle>
                {tenant.displayName || tenant.name}{" "}
                <Badge data-testid="tenant-state" variant={tenant.state === "ACTIVE" ? "default" : "secondary"}>
                  {tenant.state}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="text-sm text-muted-foreground">ID: {tenant.id}</div>
              <form
                className="flex items-end gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void lifecycle.update(displayName);
                }}
              >
                <div className="flex-1 space-y-1">
                  <Label htmlFor="tenant-display-name">Display name</Label>
                  <Input
                    id="tenant-display-name"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                  />
                </div>
                <Button type="submit" disabled={busy}>
                  Save
                </Button>
              </form>
              <div className="flex gap-2">
                {tenant.state === "SUSPENDED" ? (
                  <Button variant="outline" onClick={() => lifecycle.resume()} disabled={busy}>
                    Resume
                  </Button>
                ) : (
                  <Button variant="outline" onClick={() => setConfirm("suspend")} disabled={busy}>
                    Suspend
                  </Button>
                )}
                <Button variant="destructive" onClick={() => setConfirm("delete")} disabled={busy}>
                  Delete
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Quotas</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <form
                className="flex items-end gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void lifecycle.updateQuotas({ maxVms: Number(maxVms) });
                }}
              >
                <div className="flex-1 space-y-1">
                  <Label htmlFor="quota-max-vms">Maximum VMs</Label>
                  <Input
                    id="quota-max-vms"
                    type="number"
                    min={0}
                    value={maxVms}
                    onChange={(e) => setMaxVms(e.target.value)}
                  />
                </div>
                <Button type="submit" disabled={busy || maxVms === ""}>
                  Save quotas
                </Button>
              </form>
              <form
                className="flex items-end gap-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void lifecycle.checkQuota(resource, Number(amount));
                }}
              >
                <div className="flex-1 space-y-1">
                  <Label htmlFor="quota-resource">Resource</Label>
                  <Input id="quota-resource" value={resource} onChange={(e) => setResource(e.target.value)} />
                </div>
                <div className="w-32 space-y-1">
                  <Label htmlFor="quota-amount">Amount</Label>
                  <Input
                    id="quota-amount"
                    type="number"
                    min={1}
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                  />
                </div>
                <Button type="submit" disabled={busy || !resource}>
                  Check quota
                </Button>
              </form>
              {quotaCheck && (
                <div data-testid="quota-check-result" className="text-sm">
                  {quotaCheck.available ? "Available" : "Not available"}
                  {quotaCheck.message ? `: ${quotaCheck.message}` : ""}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Data encryption key</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex gap-2">
                <Button variant="outline" onClick={() => lifecycle.loadDEKStatus()} disabled={busy}>
                  Load DEK status
                </Button>
                <Button variant="outline" onClick={() => setConfirm("rotate")} disabled={busy}>
                  Rotate DEK
                </Button>
              </div>
              {dekStatus && (
                <dl data-testid="dek-status" className="grid grid-cols-2 gap-2 text-sm">
                  <dt>Version</dt>
                  <dd data-testid="dek-version">{dekStatus.version}</dd>
                  <dt>Algorithm</dt>
                  <dd>{dekStatus.algorithm}</dd>
                  <dt>Status</dt>
                  <dd>{dekStatus.status}</dd>
                  <dt>Usage</dt>
                  <dd>{dekStatus.usagePercent}%</dd>
                </dl>
              )}
            </CardContent>
          </Card>
        </>
      )}

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent>
          {confirm && (
            <>
              <DialogHeader>
                <DialogTitle>{CONFIRM_TEXT[confirm].title}</DialogTitle>
                <DialogDescription>{`${CONFIRM_TEXT[confirm].description} Tenant: ${tenant?.name ?? ""}.`}</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button
                  variant={confirm === "delete" ? "destructive" : "default"}
                  onClick={() => void onConfirm()}
                >
                  {CONFIRM_TEXT[confirm].label}
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
