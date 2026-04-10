"use client";

/**
 * Attestation Dashboard Page
 *
 * Features:
 * - View attestation statistics
 * - List all attestation reports
 * - View attestation details
 * - Request new attestations
 *
 * Uses the trusted-platform-sdk for API interactions.
 */

import * as React from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { AttestationTable } from "@/components/features/attestation/attestation-table";
import { useAttestation, useApi, useMutation, useToast } from "@/hooks";
import type { Attestation, AttestationStats } from "@/types/security";
import type { HostManifest } from "trusted-platform-sdk";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Clock,
  AlertCircle,
  RefreshCw,
} from "lucide-react";

export default function AttestationPage() {
  const router = useRouter();
  const { toast } = useToast();
  const attestation = useAttestation();

  // Fetch manifests using SDK
  const {
    data: manifestsData,
    isLoading: loading,
    error,
    refetch: loadData,
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

  // Helper to determine attestation status from manifest
  const getManifestStatus = (manifest: HostManifest): Attestation["status"] => {
    // If host attestation exists and has valid signature, it's verified
    if (manifest.host && manifest.signature) {
      return "verified";
    }
    // If no host attestation, it's pending
    if (!manifest.host) {
      return "pending";
    }
    return "pending";
  };

  // Transform SDK manifests to local Attestation type for UI compatibility
  const attestations: Attestation[] = React.useMemo(() => {
    if (!manifestsData?.manifests) return [];
    return manifestsData.manifests.map((m: HostManifest) => ({
      id: m.id,
      deviceId: m.hostId || "",
      deviceName: m.hostId || "Unknown Device",
      tpmManufacturer: m.host?.firmwareVersion || "Unknown",
      status: getManifestStatus(m),
      attestedAt: m.timestamp || new Date().toISOString(),
    }));
  }, [manifestsData]);

  // Compute stats from attestations
  const stats: AttestationStats = React.useMemo(() => {
    return {
      total: attestations.length,
      verified: attestations.filter((a) => a.status === "verified").length,
      failed: attestations.filter((a) => a.status === "failed").length,
      pending: attestations.filter((a) => a.status === "pending").length,
    };
  }, [attestations]);

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
        <Button variant="outline" onClick={() => loadData()} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
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

      {/* Statistics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Attestations</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.total}</div>
            <p className="text-xs text-muted-foreground">
              All attestation reports
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Verified</CardTitle>
            <ShieldCheck className="h-4 w-4 text-green-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
              {stats.verified}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats.total > 0
                ? `${((stats.verified / stats.total) * 100).toFixed(1)}%`
                : "0%"}{" "}
              of total
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Failed</CardTitle>
            <ShieldAlert className="h-4 w-4 text-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-destructive">
              {stats.failed}
            </div>
            <p className="text-xs text-muted-foreground">
              {stats.total > 0
                ? `${((stats.failed / stats.total) * 100).toFixed(1)}%`
                : "0%"}{" "}
              of total
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Pending</CardTitle>
            <Clock className="h-4 w-4 text-orange-500" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-orange-600 dark:text-orange-400">
              {stats.pending}
            </div>
            <p className="text-xs text-muted-foreground">
              Awaiting verification
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Attestations Table */}
      <div>
        <h2 className="text-xl font-semibold mb-4">Recent Attestations</h2>
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
