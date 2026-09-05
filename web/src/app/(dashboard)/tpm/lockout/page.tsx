"use client";

/**
 * TPM Lockout Management Page
 *
 * Surfaces the dictionary-attack (DA) protection state of the TPM:
 * the current LockoutCounter, the recovery interval, the
 * MaxAuthFail threshold, and whether the lockout hierarchy is
 * presently locked.
 *
 * Data source: the structured `capabilities[]` array on
 * /api/v1/tpm/info (server populates from
 * pkg/api/daemon/tpm_grpc_service.go::Info via xkms's
 * FixedProperties()). This is the canonical surface — we don't
 * re-parse the free-form `properties.info` text dump here.
 *
 * Modeled after the xkey TPM Svelte view's "Lockout" category;
 * see memory `reference_xkey_tpm_gui.md`.
 */

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  RefreshCw,
  Lock,
  AlertCircle,
  ShieldAlert,
  Clock,
  Activity,
} from "lucide-react";
import { useApi, useTPM, useToast } from "@/hooks";
import type { TPMCapability } from "trusted-platform-sdk";


const findCapability = (caps: TPMCapability[] | undefined, name: string) =>
  caps?.find((c) => c.name === name);

const formatSeconds = (seconds: number): string => {
  if (seconds === 0) return "0";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
};

export default function TPMLockoutPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  const {
    data: tpmInfo,
    isLoading: loading,
    error,
    refetch,
  } = useApi(
    () => tpm.getInfo(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading TPM info",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const lockout = React.useMemo(() => {
    const caps = tpmInfo?.capabilities;
    const counter = parseInt(findCapability(caps, "lockoutCounter")?.value || "0", 10);
    const intervalSec = parseInt(findCapability(caps, "lockoutInterval")?.value || "0", 10);
    const recoverySec = parseInt(findCapability(caps, "lockoutRecovery")?.value || "0", 10);
    const maxAuthFail = parseInt(findCapability(caps, "maxAuthFail")?.value || "0", 10);
    return {
      counter,
      maxAuthFail,
      intervalSec,
      recoverySec,
      // The TPM is "in lockout" when the failed-auth counter has
      // hit the configured threshold. Most TPMs let the counter
      // tick down by one every `intervalSec` of normal operation.
      isLockedOut: maxAuthFail > 0 && counter >= maxAuthFail,
      utilizationPct: maxAuthFail > 0 ? Math.min(100, Math.round((counter / maxAuthFail) * 100)) : 0,
    };
  }, [tpmInfo]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">TPM Lockout</h1>
          <p className="text-muted-foreground">
            Dictionary-attack protection state &mdash; counter, recovery
            interval, and failure threshold for the LOCKOUT hierarchy
          </p>
        </div>
        <Button variant="outline" onClick={() => refetch()} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      {!loading && tpmInfo && (
        <>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Lockout State</CardTitle>
                {lockout.isLockedOut ? (
                  <ShieldAlert className="h-4 w-4 text-destructive" />
                ) : (
                  <Lock className="h-4 w-4 text-muted-foreground" />
                )}
              </CardHeader>
              <CardContent>
                <Badge variant={lockout.isLockedOut ? "destructive" : "default"} className="text-lg px-3 py-1">
                  {lockout.isLockedOut ? "Locked Out" : "Operational"}
                </Badge>
                <p className="text-xs text-muted-foreground mt-2">
                  {lockout.isLockedOut
                    ? "Failed auth threshold reached &mdash; LOCKOUT hierarchy refuses commands until recovery"
                    : "Auth counter below failure threshold"}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Counter</CardTitle>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">
                  {lockout.counter}
                  <span className="text-base font-normal text-muted-foreground"> / {lockout.maxAuthFail}</span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Failed authorization attempts ({lockout.utilizationPct}%)
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Recovery Interval</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{formatSeconds(lockout.recoverySec)}</div>
                <p className="text-xs text-muted-foreground">
                  After recovery the counter is fully cleared
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Tick Interval</CardTitle>
                <Clock className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{formatSeconds(lockout.intervalSec)}</div>
                <p className="text-xs text-muted-foreground">
                  Counter decrements by 1 per interval
                </p>
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Lockout Mechanics</CardTitle>
              <CardDescription>
                How TPM 2.0 dictionary-attack protection works
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 text-sm text-muted-foreground">
              <p>
                The LOCKOUT hierarchy maintains a failure counter that increments on
                every <code>TPM_RC_BAD_AUTH</code> against any of its protected
                resources. When the counter reaches <strong>maxAuthFail</strong> the
                hierarchy refuses further authorization attempts until a recovery
                window passes or <code>TPM2_DictionaryAttackLockReset</code> is
                invoked with the lockout authorization.
              </p>
              <p>
                On this platform the counter is currently <strong>{lockout.counter}</strong>{" "}
                of <strong>{lockout.maxAuthFail}</strong>. Each <em>{formatSeconds(lockout.intervalSec)}</em>{" "}
                of normal operation drops the counter by one. A full recovery
                window is <strong>{formatSeconds(lockout.recoverySec)}</strong>, after
                which the counter zeroes regardless of state.
              </p>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium text-foreground mb-2">Counter Behavior</h4>
                  <ul className="list-disc list-inside space-y-1">
                    <li>Increments on <code>TPM_RC_AUTH_FAIL</code></li>
                    <li>Decrements every <em>tick interval</em></li>
                    <li>Resets after <em>recovery interval</em></li>
                    <li>Clearable via <code>TPM2_DictionaryAttackLockReset</code></li>
                  </ul>
                </div>
                <div>
                  <h4 className="font-medium text-foreground mb-2">Reset Paths</h4>
                  <ul className="list-disc list-inside space-y-1">
                    <li>Lockout hierarchy auth (typical)</li>
                    <li>Owner hierarchy auth (some flows)</li>
                    <li>UEFI PPI ForceClear (firmware-level)</li>
                    <li>Power cycle does <strong>not</strong> reset the counter</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
