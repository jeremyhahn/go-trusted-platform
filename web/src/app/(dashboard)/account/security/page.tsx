"use client";

/**
 * Account → Security page (/account/security)
 *
 * Displays the user's registered auth factors (mTLS, FIDO2, PIV) grouped by type.
 * Tenant admins can toggle the "Require N factors" policy.
 */

import { useState } from "react";
import { Plus, Shield, ShieldCheck, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { useApi, useToast } from "@/hooks";
import { useAuth } from "@/contexts/AuthContext";
import { FactorList } from "@/components/security/factor-list";
import { AddFactorWizard } from "@/components/security/add-factor-wizard";
import { authFactorsApi, toApiResponse } from "@/utils/auth-factors-api";
import type { AuthFactor } from "@/types/auth-factors";

export default function AccountSecurityPage() {
  const { toast } = useToast();
  const { user } = useAuth();


  // Wizard state
  const [wizardOpen, setWizardOpen] = useState(false);
  const [rotateTarget, setRotateTarget] = useState<AuthFactor | null>(null);

  // MFA policy state (tenant admin only)
  const [requireMFA, setRequireMFA] = useState(false);
  const [mfaPolicyBusy, setMFAPolicyBusy] = useState(false);

  const isTenantAdmin = user?.isTenantOwner ?? false;
  const userId = user?.id;

  // The SDK's useApi owns the load: it fetches when userId is known, refetches
  // on demand, and holds the list. Local edits go through its mutate.
  const {
    data: factorList,
    error: loadError,
    isLoading,
    refetch,
    mutate,
  } = useApi(
    () => authFactorsApi.list(userId ?? "").then(toApiResponse),
    [userId],
    { enabled: !!userId }
  );

  const factors = factorList?.factors ?? [];
  // No userId yet means the list cannot be fetched; show it as loading.
  const loading = !userId || isLoading;

  // Apply a local edit to the list; `total` moves by the entries it added.
  function updateFactors(update: (prev: AuthFactor[]) => AuthFactor[]) {
    mutate((prev) => {
      const previous = prev?.factors ?? [];
      const next = update(previous);
      return {
        factors: next,
        total: (prev?.total ?? previous.length) + next.length - previous.length,
      };
    });
  }

  async function handleRemove(factor: AuthFactor) {
    if (!user?.id) return;
    const result = await authFactorsApi.remove(user.id, factor.id);
    if (!result.ok) {
      toast({ title: "Error removing factor", description: result.error, variant: "destructive" });
      return;
    }
    toast({ title: "Factor removed", description: `"${factor.label}" has been removed.` });
    await refetch();
  }

  async function handleRelabel(factor: AuthFactor, label: string) {
    if (!user?.id) return;
    const result = await authFactorsApi.relabel(user.id, { factor_id: factor.id, label });
    if (!result.ok) {
      toast({ title: "Error updating label", description: result.error, variant: "destructive" });
      return;
    }
    updateFactors((prev) =>
      prev.map((f) => (f.id === factor.id ? { ...f, label } : f))
    );
  }

  function handleRotate(factor: AuthFactor) {
    setRotateTarget(factor);
    setWizardOpen(true);
  }

  function handleAdded(factor: AuthFactor) {
    updateFactors((prev) => {
      if (rotateTarget) {
        // Mark the old factor revoked in UI immediately
        return prev
          .map((f) =>
            f.id === rotateTarget.id
              ? { ...f, revoked_at: new Date().toISOString() }
              : f
          )
          .concat(factor);
      }
      return [...prev, factor];
    });
  }

  async function handleMFAPolicyToggle(checked: boolean) {
    if (!user?.tenantId) return;
    setMFAPolicyBusy(true);
    const result = await authFactorsApi.setMFAPolicy({
      tenant_id: user.tenantId,
      require_multiple_factors: checked,
      min_factor_count: checked ? 2 : 1,
    });
    setMFAPolicyBusy(false);
    if (!result.ok) {
      toast({ title: "Error updating MFA policy", description: result.error, variant: "destructive" });
      return;
    }
    setRequireMFA(checked);
    toast({
      title: checked ? "MFA required" : "MFA optional",
      description: checked
        ? "Users must present at least 2 factors per session."
        : "Single factor is sufficient for a session.",
    });
  }

  return (
    <div className="container max-w-2xl py-8 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="h-6 w-6" />
            Security
          </h1>
          <p className="text-muted-foreground mt-1">
            Manage the authentication factors used to sign in to your account.
          </p>
        </div>
        <Button
          onClick={() => {
            setRotateTarget(null);
            setWizardOpen(true);
          }}
          disabled={loading}
          aria-label="Add authentication factor"
        >
          <Plus className="h-4 w-4 mr-2" />
          Add factor
        </Button>
      </div>

      {loadError && (
        <Alert variant="destructive">
          <AlertTitle>Failed to load factors</AlertTitle>
          <AlertDescription>
            {loadError.message}
            <Button
              variant="link"
              size="sm"
              className="p-0 h-auto ml-2"
              onClick={() => void refetch()}
            >
              Retry
            </Button>
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" />
            Authentication factors
          </CardTitle>
          <CardDescription>
            You can sign in with any one of the factors listed below. Add
            multiple factors as backups.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FactorList
            factors={factors}
            loading={loading}
            onRotate={handleRotate}
            onRemove={handleRemove}
            onRelabel={handleRelabel}
          />
        </CardContent>
      </Card>

      {isTenantAdmin && (
        <Card>
          <CardHeader>
            <CardTitle>Session policy</CardTitle>
            <CardDescription>
              As a tenant administrator you can require users in your tenant to
              present multiple factors per session.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-3">
              <Switch
                id="require-mfa"
                checked={requireMFA}
                onCheckedChange={handleMFAPolicyToggle}
                disabled={mfaPolicyBusy}
                aria-label="Require 2 factors per session"
              />
              <Label htmlFor="require-mfa" className="cursor-pointer">
                Require 2 or more factors per session
              </Label>
              {mfaPolicyBusy && (
                <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <AddFactorWizard
        open={wizardOpen}
        onOpenChange={(open) => {
          setWizardOpen(open);
          if (!open) setRotateTarget(null);
        }}
        userId={user?.id ?? ""}
        onAdded={handleAdded}
        rotateFactorId={rotateTarget?.id}
        rotateFactorType={rotateTarget?.type}
      />
    </div>
  );
}
