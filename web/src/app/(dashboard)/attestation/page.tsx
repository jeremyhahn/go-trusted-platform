"use client";

/**
 * Attestation Dashboard Page
 *
 * Features:
 * - The fleet's verifier verdicts: verified, failed, not verified, stale
 * - Problems an operator must act on, including a verifier that has stopped
 * - List host manifests (signed evidence, not verdicts)
 * - Request new manifests
 *
 * The summary counts the collector's cached device reports — the verifier's
 * own verdicts — never the manifests (#643). Counting manifests called every
 * manifest without a host section "pending" forever, so a fleet nothing had
 * verified read as a clean dashboard.
 *
 * Uses the trusted-platform-sdk for API interactions.
 */

import * as React from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { AttestationTable } from "@/components/features/attestation/attestation-table";
import { useAttestation, useApi, useMutation, useToast } from "@/hooks";
import {
  fleetAttestationProblems,
  fleetReportsState,
  summarizeReports,
} from "@/lib/attestation-report";
import type { Attestation } from "@/types/security";
import type { HostManifest } from "trusted-platform-sdk";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  AlertCircle,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";

function percentOf(count: number, total: number): string {
  return total > 0 ? `${((count / total) * 100).toFixed(1)}%` : "0%";
}

export default function AttestationPage() {
  const router = useRouter();
  const { toast } = useToast();
  const attestation = useAttestation();

  // The verifier's cached verdicts, one per collected device
  const {
    data: reportsData,
    isLoading: reportsLoading,
    error: reportsError,
    refetch: loadReports,
  } = useApi(() => attestation.listDeviceReports(), []);
  const reportsState = fleetReportsState(reportsLoading, reportsError);
  const summary = React.useMemo(
    () => summarizeReports(reportsData?.reports ?? []),
    [reportsData]
  );
  const problems = fleetAttestationProblems(summary, reportsState);

  // Host manifests: signed evidence documents, listed below the verdicts
  const {
    data: manifestsData,
    isLoading: loading,
    error,
    refetch: loadManifests,
  } = useApi(
    () => attestation.listManifests(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading attestations",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const loadData = () => {
    loadManifests();
    loadReports();
  };

  // Transform SDK manifests to local Attestation type for UI compatibility.
  // A signature makes a manifest signed evidence; only the verifier issues a
  // verdict, and that is the device report counted above.
  const attestations: Attestation[] = React.useMemo(() => {
    if (!manifestsData?.manifests) return [];
    return manifestsData.manifests.map((m: HostManifest) => ({
      id: m.id,
      deviceId: m.hostId || "",
      deviceName: m.hostId || "Unknown Device",
      tpmManufacturer: m.host?.firmwareVersion || "Unknown",
      status: m.signature ? ("signed" as const) : ("unsigned" as const),
      attestedAt: m.timestamp || new Date().toISOString(),
    }));
  }, [manifestsData]);

  // Request attestation mutation (builds a new manifest)
  const requestMutation = useMutation(
    async (params: { hostId: string }) => {
      return attestation.buildManifest({
        config: { hostId: params.hostId },
        includeVms: true,
        includeContainers: true,
        sign: true,
      });
    },
    {
      onSuccess: () => {
        toast({
          title: "Attestation requested",
          description: "Attestation requested successfully",
          variant: "success",
        });
        loadData();
      },
      onError: (err) => {
        toast({
          title: "Attestation request failed",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleView = (attestationItem: Attestation) => {
    router.push(`/attestation/${encodeURIComponent(attestationItem.id)}`);
  };

  const handleRequestAttestation = async (attestationItem: Attestation) => {
    if (!confirm(`Request new attestation for device "${attestationItem.deviceName}"?`)) {
      return;
    }
    requestMutation.mutate({ hostId: attestationItem.deviceId });
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Attestation</h1>
          <p className="text-muted-foreground">
            Monitor and verify TPM-based device attestations
          </p>
        </div>
        <Button variant="outline" onClick={() => loadData()} disabled={loading || reportsLoading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading || reportsLoading ? "animate-spin" : ""}`} />
          Refresh
        </Button>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error.message}</p>
          </div>
        </div>
      )}

      {/* Problems: verdicts nobody is acting on, or a verifier that has stopped */}
      {problems.length > 0 && (
        <Alert variant="destructive" data-testid="attestation-fleet-problems">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Attestation needs attention</AlertTitle>
          <AlertDescription>
            <ul className="mt-1 list-disc space-y-1 pl-4">
              {problems.map((problem) => (
                <li key={problem}>{problem}</li>
              ))}
            </ul>
          </AlertDescription>
        </Alert>
      )}

      {reportsState === "error" && reportsError && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Device verdicts unavailable</p>
            <p className="text-sm text-destructive">{reportsError.message}</p>
          </div>
        </div>
      )}

      {/* Verdict Cards: the verifier's cached verdicts, one per device */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Devices Reporting</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="attestation-stat-total">
              {summary.total}
            </div>
            <p className="text-xs text-muted-foreground">
              Devices with a verifier verdict
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Verified</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div
              className="text-2xl font-bold text-green-600 dark:text-green-400"
              data-testid="attestation-stat-verified"
            >
              {summary.verified}
            </div>
            <p className="text-xs text-muted-foreground">
              {percentOf(summary.verified, summary.total)} of devices
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive" data-testid="attestation-stat-failed">
              {summary.failed}
            </div>
            <p className="text-xs text-muted-foreground">
              A check ran and failed
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Not Verified</CardTitle>
            <ShieldQuestion className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div
              className="text-2xl font-bold text-orange-600 dark:text-orange-400"
              data-testid="attestation-stat-not-verified"
            >
              {summary.notVerified}
            </div>
            <p className="text-xs text-muted-foreground" data-testid="attestation-stat-stale">
              No verdict reached · {summary.stale} stale
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Host Manifests Table */}
      <div>
        <h2 className="text-xl font-semibold mb-1">Host Manifests</h2>
        <p className="text-sm text-muted-foreground mb-4">
          Signed evidence documents. A manifest is not a verdict: each device&apos;s
          verdict is counted above and shown on the Devices page.
        </p>
        <AttestationTable
          attestations={attestations}
          onView={handleView}
          onRequestAttestation={handleRequestAttestation}
          loading={loading}
        />
      </div>
    </div>
  );
}
