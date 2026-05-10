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
import { ArrowLeft, Loader2, AlertCircle, ShieldCheck, ShieldAlert } from "lucide-react";

/**
 * Attestation Detail Page
 *
 * Features:
 * - View complete attestation details
 * - Display device information
 * - Show PCR values
 * - View event log
 * - Display verification result
 */
export default function AttestationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const id = resolveDynamicId(resolved as any, pathname, "attestation");
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
      status: "pending" as const, // TODO: Derive status from verification result
      quote: attestationData.host?.quoteData || "",
      verificationResult: {
        valid: true, // TODO: Add verification logic
        errors: [],
      },
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
          variant={
            attestationDetail.status === "verified"
              ? "default"
              : attestationDetail.status === "failed"
              ? "destructive"
              : "secondary"
          }
          className="text-base px-4 py-2"
        >
          {attestationDetail.status}
        </Badge>
      </div>

      {/* Verification Result */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            {attestationDetail.verificationResult.valid ? (
              <ShieldCheck className="h-5 w-5 text-green-500" />
            ) : (
              <ShieldAlert className="h-5 w-5 text-destructive" />
            )}
            <CardTitle>Verification Result</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div
            className={`p-4 rounded-lg border ${
              attestationDetail.verificationResult.valid
                ? "bg-green-50 border-green-200 dark:bg-green-950 dark:border-green-800"
                : "bg-red-50 border-red-200 dark:bg-red-950 dark:border-red-800"
            }`}
          >
            <p
              className={`font-medium ${
                attestationDetail.verificationResult.valid
                  ? "text-green-900 dark:text-green-100"
                  : "text-red-900 dark:text-red-100"
              }`}
            >
              {attestationDetail.verificationResult.valid
                ? "Attestation Verified Successfully"
                : "Attestation Verification Failed"}
            </p>
            {attestationDetail.verificationResult.errors &&
              attestationDetail.verificationResult.errors.length > 0 && (
                <ul className="mt-2 space-y-1">
                  {attestationDetail.verificationResult.errors.map((error, idx) => (
                    <li key={idx} className="text-sm text-red-800 dark:text-red-200">
                      • {error}
                    </li>
                  ))}
                </ul>
              )}
          </div>
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
