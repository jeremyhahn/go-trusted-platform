"use client";

import * as React from "react";
import { use } from "react";
import { usePathname, useRouter } from "next/navigation";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { PCRValues } from "@/components/features/attestation/pcr-values";
import { EventLogViewer } from "@/components/features/attestation/event-log-viewer";
import { useAttestation, useApi } from "@/hooks";
import type { AttestationDetail } from "@/types/security";
import { ArrowLeft, Loader2, AlertCircle, ShieldQuestion } from "lucide-react";

/**
 * Attestation Detail Page
 *
 * Features:
 * - View complete attestation details
 * - Display device information
 * - Show PCR values
 * - View event log
 * - Point at the verifier's verdict: a manifest is signed or unsigned
 *   evidence, never a verdict (#643)
 */
export default function AttestationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const id = resolveDynamicId(resolved, pathname, "attestation");
  const router = useRouter();
  const attestation = useAttestation();

  // TODO: The SDK getManifest method returns a full manifest. For now, we're using it
  // to fetch attestation details. A dedicated getAttestationStatus method should be added
  // to the SDK for better separation of concerns.
  const { data: response, isLoading: loading, error } = useApi(
    () => attestation.getManifest(id),
    [id]
  );

  const attestationData = response?.manifest;

  const attestationDetail: AttestationDetail | null = React.useMemo(() => {
    if (!attestationData) return null;

    return {
      id: id,
      deviceId: attestationData.hostId || id,
      deviceName: attestationData.hostId || "Unknown Device",
      tpmManufacturer: attestationData.host?.akPublicKey ? "TPM 2.0" : "Unknown",
      attestedAt: attestationData.timestamp || new Date().toISOString(),
      status: attestationData.signature ? ("signed" as const) : ("unsigned" as const),
      quote: attestationData.host?.quoteData || "",
      deviceInfo: {
        tpmVersion: "2.0",
        firmwareVersion: attestationData.host?.firmwareVersion || "Unknown",
        bootMode: "UEFI",
      },
      // Convert PCR values from array to object
      pcrValues: attestationData.host?.pcrs?.reduce((acc: Record<number, string>, pcr) => {
        acc[pcr.index] = pcr.value;
        return acc;
      }, {}) || {},
      // Event log would need to be decoded from base64
      eventLog: attestationData.host?.quoteData ? [
        {
          pcrIndex: 0,
          eventType: "TPM Quote",
          digest: attestationData.host.pcrDigest || "",
          data: attestationData.host.quoteData,
        }
      ] : [],
    };
  }, [attestationData, id]);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <AlertCircle className="h-12 w-12 text-destructive" />
        <div className="text-center">
          <p className="font-medium text-destructive">Error loading attestation</p>
          <p className="text-sm text-muted-foreground">{error.message}</p>
        </div>
        <Button variant="outline" onClick={() => router.push("/attestation")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Attestations
        </Button>
      </div>
    );
  }

  if (!attestationDetail) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <p className="text-muted-foreground">Attestation not found</p>
        <Button variant="outline" onClick={() => router.push("/attestation")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Attestations
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => router.push("/attestation")}>
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div>
            <h1 className="text-3xl font-bold tracking-tight">{attestationDetail.deviceName}</h1>
            <p className="text-muted-foreground">Attestation report details</p>
          </div>
        </div>
        <Badge
          variant={attestationDetail.status === "signed" ? "outline" : "secondary"}
          className="text-base px-4 py-2"
        >
          {attestationDetail.status === "signed" ? "Signed" : "Unsigned"}
        </Badge>
      </div>

      {/* Verification Result: a manifest is evidence; the verifier's verdict is the device report (#643) */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <ShieldQuestion className="h-5 w-5 text-muted-foreground" />
            <CardTitle>Verification Result</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm text-muted-foreground" data-testid="manifest-not-a-verdict">
            This manifest is evidence, not a verdict. The control plane&apos;s collector
            verifies each device&apos;s quote and serves the verdict with its age as the
            device&apos;s attestation report.
          </p>
          <Button variant="outline" size="sm" onClick={() => router.push("/devices")}>
            View device verdicts
          </Button>
        </CardContent>
      </Card>

      {/* Device Information */}
      <Card>
        <CardHeader>
          <CardTitle>Device Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Device ID</div>
              <code className="mt-1 text-xs bg-muted px-2 py-1 rounded">
                {attestationDetail.deviceId}
              </code>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Device Name</div>
              <div className="mt-1 text-sm">{attestationDetail.deviceName}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">TPM Manufacturer</div>
              <Badge variant="outline" className="mt-1">
                {attestationDetail.tpmManufacturer}
              </Badge>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Attested At</div>
              <div className="mt-1 text-sm">
                {new Date(attestationDetail.attestedAt).toLocaleString()}
              </div>
            </div>
          </div>

          <Separator />

          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">TPM Version</div>
              <div className="mt-1 text-sm">{attestationDetail.deviceInfo.tpmVersion}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Firmware Version</div>
              <div className="mt-1 text-sm">{attestationDetail.deviceInfo.firmwareVersion}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Boot Mode</div>
              <Badge variant="outline" className="mt-1">
                {attestationDetail.deviceInfo.bootMode}
              </Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quote Data */}
      <Card>
        <CardHeader>
          <CardTitle>TPM Quote</CardTitle>
          <CardDescription>Signed attestation quote from the TPM</CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="text-xs bg-muted p-4 rounded overflow-x-auto border">
            {attestationDetail.quote}
          </pre>
        </CardContent>
      </Card>

      {/* PCR Values */}
      <PCRValues pcrValues={attestationDetail.pcrValues} />

      {/* Event Log */}
      <EventLogViewer eventLog={attestationDetail.eventLog} />
    </div>
  );
}
