"use client";

/**
 * Admin tenant detail (#1673): UpdateTenant, SuspendTenant, ResumeTenant,
 * UpdateQuotas, CheckQuota, Sync, RotateTenantDEK, GetTenantDEKStatus and the
 * tenant barrier (init, unseal, seal). Suspend, DEK rotation and seal ask
 * through a confirm dialog first.
 */
import * as React from "react";
import Link from "next/link";
import { useParams, usePathname } from "next/navigation";
import { useApi, useTenant } from "@/hooks";
import { resolveDynamicId } from "@/utils/dynamic-route";
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Input,
  Label,
} from "@/components/ui";
import { ConfirmDialog, errorText, type PendingAction } from "../confirm-dialog";
import { tenantStateName } from "../tenant-state";

function toNumber(v: string): number | undefined {
  if (v.trim() === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

export default function TenantDetailClient() {
  const params = useParams();
  const pathname = usePathname();
  const tenantId = resolveDynamicId(params, pathname, "tenants");
  const tenants = useTenant();

  const {
    data: tenantData,
    isLoading,
    error,
    refetch,
  } = useApi(() => tenants.getTenant(tenantId), [tenantId], { enabled: !!tenantId });
  const { data: dekData, refetch: refetchDEK } = useApi(
    () => tenants.getDEKStatus(tenantId),
    [tenantId],
    { enabled: !!tenantId }
  );

  const [status, setStatus] = React.useState("");
  const [pending, setPending] = React.useState<PendingAction | null>(null);
  const [displayName, setDisplayName] = React.useState<string | null>(null);
  const [maxVms, setMaxVms] = React.useState("");
  const [maxVcpus, setMaxVcpus] = React.useState("");
  const [maxMemoryMb, setMaxMemoryMb] = React.useState("");
  const [checkResource, setCheckResource] = React.useState("vms");
  const [checkAmount, setCheckAmount] = React.useState("1");
  const [unsealKey, setUnsealKey] = React.useState("");

  const tenant = tenantData?.tenant;
  const dek = dekData?.dekStatus;
  const shownDisplayName = displayName ?? tenant?.displayName ?? "";

  const report = (res: { success: boolean; error?: { message?: string } }, ok: string, fail: string) =>
    setStatus(res.success ? ok : errorText(res, fail));

  const saveDisplayName = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.updateTenant({ tenantId, displayName: shownDisplayName });
    report(res, "Tenant updated", "Update failed");
    if (res.success) {
      setDisplayName(null);
      await refetch();
    }
  };

  const suspend = () =>
    setPending({
      title: "Suspend this tenant?",
      description: "Its members lose access until the tenant is resumed.",
      confirmLabel: "Suspend",
      run: async () => {
        const res = await tenants.suspendTenant(tenantId);
        report(res, "Tenant suspended", "Suspend failed");
        if (res.success) await refetch();
      },
    });

  const resume = async () => {
    const res = await tenants.resumeTenant(tenantId);
    report(res, "Tenant resumed", "Resume failed");
    if (res.success) await refetch();
  };

  const saveQuotas = async (e: React.FormEvent) => {
    e.preventDefault();
    // The server replaces every limit of a supplied compute section, so send
    // the current limits for the fields that were not edited.
    const cur: Record<string, unknown> = { ...(tenant?.computeQuota ?? {}) };
    const keep = (edited: string, current: unknown) => toNumber(edited) ?? (Number(current ?? 0) || 0);
    const res = await tenants.updateQuotas({
      tenantId,
      compute: {
        maxVms: keep(maxVms, cur.maxVms),
        maxContainers: keep("", cur.maxContainers),
        maxVcpus: keep(maxVcpus, cur.maxVcpus),
        maxMemoryMb: keep(maxMemoryMb, cur.maxMemoryMb),
      },
    });
    report(res, "Quotas updated", "Quota update failed");
    if (res.success) {
      setMaxVms("");
      setMaxVcpus("");
      setMaxMemoryMb("");
      await refetch();
    }
  };

  const checkQuota = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.checkQuota({
      tenantId,
      resource: checkResource,
      amount: toNumber(checkAmount) ?? 0,
    });
    if (res.success && res.data) {
      setStatus(
        res.data.available
          ? `Quota available for ${res.data.amount} ${res.data.resource}`
          : `Quota exceeded for ${res.data.amount} ${res.data.resource}${res.data.message ? `: ${res.data.message}` : ""}`
      );
    } else {
      setStatus(errorText(res, "Quota check failed"));
    }
  };

  const sync = async () => {
    const res = await tenants.syncTenants();
    report(res, "Tenants synced", "Sync failed");
  };

  const rotateDEK = () =>
    setPending({
      title: "Rotate this tenant's DEK?",
      description: "A new data encryption key version is created and data is re-encrypted.",
      confirmLabel: "Rotate",
      run: async () => {
        const res = await tenants.rotateDEK({ tenantId });
        if (res.success && res.data) {
          setStatus(`DEK rotated from version ${res.data.oldVersion} to ${res.data.newVersion}`);
          await refetchDEK();
        } else {
          setStatus(errorText(res, "DEK rotation failed"));
        }
      },
    });

  const initBarrier = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.initBarrier({ tenantId });
    report(res, "Barrier initialised", "Barrier init failed");
  };

  const unsealBarrier = async (e: React.FormEvent) => {
    e.preventDefault();
    const res = await tenants.unsealBarrier({ tenantId, key: unsealKey });
    report(res, "Barrier unsealed", "Barrier unseal failed");
    if (res.success) setUnsealKey("");
  };

  const sealBarrier = () =>
    setPending({
      title: "Seal this tenant's barrier?",
      description: "The tenant's secrets are unreadable until the barrier is unsealed again.",
      confirmLabel: "Seal",
      run: async () => {
        const res = await tenants.sealBarrier(tenantId);
        report(res, "Barrier sealed", "Barrier seal failed");
      },
    });

  if (isLoading) return <p>Loading tenant...</p>;
  if (error || !tenant) return <p role="alert">Failed to load tenant: {error?.message ?? "not found"}</p>;
  const stateName = tenantStateName(tenant.state);

  return (
    <div className="space-y-6">
      <Link href="/admin/tenants/">Back to tenants</Link>
      <div className="flex items-center gap-3">
        <h2 className="text-2xl font-semibold">{tenant.name}</h2>
        <Badge data-testid="tenant-state" variant={stateName === "ACTIVE" ? "default" : "secondary"}>
          {stateName}
        </Badge>
      </div>
      <p role="status" data-testid="action-result">
        {status}
      </p>

      <Card>
        <CardHeader>
          <CardTitle>Details</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <form onSubmit={saveDisplayName} className="flex items-end gap-3">
            <div>
              <Label htmlFor="detail-display-name">Display name</Label>
              <Input
                id="detail-display-name"
                value={shownDisplayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <Button type="submit">Save</Button>
          </form>
          <div className="flex gap-3">
            {stateName === "SUSPENDED" ? (
              <Button onClick={resume}>Resume</Button>
            ) : (
              <Button variant="destructive" onClick={suspend}>
                Suspend
              </Button>
            )}
            <Button variant="outline" onClick={sync}>
              Sync tenants
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Quotas</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p data-testid="current-quota">
            VMs {tenant.computeQuota?.maxVms ?? "-"}, vCPUs {tenant.computeQuota?.maxVcpus ?? "-"}, memory{" "}
            {tenant.computeQuota?.maxMemoryMb ?? "-"} MB
          </p>
          <form onSubmit={saveQuotas} className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="quota-max-vms">Max VMs</Label>
              <Input id="quota-max-vms" value={maxVms} onChange={(e) => setMaxVms(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="quota-max-vcpus">Max vCPUs</Label>
              <Input id="quota-max-vcpus" value={maxVcpus} onChange={(e) => setMaxVcpus(e.target.value)} />
            </div>
            <div>
              <Label htmlFor="quota-max-memory">Max memory (MB)</Label>
              <Input
                id="quota-max-memory"
                value={maxMemoryMb}
                onChange={(e) => setMaxMemoryMb(e.target.value)}
              />
            </div>
            <Button type="submit">Save quotas</Button>
          </form>
          <form onSubmit={checkQuota} className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="check-resource">Resource</Label>
              <Input
                id="check-resource"
                value={checkResource}
                onChange={(e) => setCheckResource(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="check-amount">Amount</Label>
              <Input id="check-amount" value={checkAmount} onChange={(e) => setCheckAmount(e.target.value)} />
            </div>
            <Button type="submit">Check quota</Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Data encryption key</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {dek ? (
            <p data-testid="dek-status">
              Version {dek.version}, {dek.algorithm}, {dek.status}, usage {dek.usagePercent}%
              {dek.needsRotation ? ", needs rotation" : ""}
            </p>
          ) : (
            <p data-testid="dek-status">DEK status unavailable</p>
          )}
          <Button variant="destructive" onClick={rotateDEK}>
            Rotate DEK
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Barrier</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <form onSubmit={initBarrier} className="flex flex-wrap items-end gap-3">
            <p className="text-sm text-muted-foreground">
              Shamir threshold and shares are not supported for tenant barriers.
            </p>
            <Button type="submit">Initialise barrier</Button>
          </form>
          <form onSubmit={unsealBarrier} className="flex flex-wrap items-end gap-3">
            <div>
              <Label htmlFor="barrier-key">Unseal key (base64)</Label>
              <Input
                id="barrier-key"
                type="password"
                value={unsealKey}
                onChange={(e) => setUnsealKey(e.target.value)}
                required
              />
            </div>
            <Button type="submit">Unseal barrier</Button>
          </form>
          <Button variant="destructive" onClick={sealBarrier}>
            Seal barrier
          </Button>
        </CardContent>
      </Card>

      <ConfirmDialog action={pending} onClose={() => setPending(null)} />
    </div>
  );
}
