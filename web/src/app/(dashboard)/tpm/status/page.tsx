"use client";

/**
 * TPM Status Page
 *
 * Features:
 * - Display TPM availability and status
 * - Show TPM manufacturer and version information
 * - Display capability flags
 * - Show lockout and authentication status
 *
 * Uses the trusted-platform-sdk for API interactions.
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
  Shield,
  ShieldCheck,
  Cpu,
  HardDrive,
  Key,
  AlertCircle,
} from "lucide-react";
import { useTPM, useApi, useToast } from "@/hooks";

/**
 * TPM Status and Information types
 */
interface TPMInfo {
  manufacturer: string;
  manufacturerId: string;
  vendorString: string;
  specVersion: string;
  specLevel: number;
  specRevision: number;
  firmwareVersion: string;
  familyIndicator: string;
  lockoutCounter: number;
  lockoutRecovery: number;
  maxAuthFail: number;
}

interface TPMCapabilities {
  hasEK: boolean;
  hasSRK: boolean;
  hasOwner: boolean;
  ownerAuthSet: boolean;
  endorsementAuthSet: boolean;
  lockoutAuthSet: boolean;
  isPhysicalPresenceEnabled: boolean;
  isPlatformHierarchyEnabled: boolean;
  isStorageHierarchyEnabled: boolean;
  isEndorsementHierarchyEnabled: boolean;
}

interface TPMStatus {
  available: boolean;
  enabled: boolean;
  activated: boolean;
  owned: boolean;
  info: TPMInfo;
  capabilities: TPMCapabilities;
}

export default function TPMStatusPage() {
  const { toast } = useToast();
  const tpm = useTPM();

  // Fetch TPM info using SDK
  const {
    data: infoData,
    isLoading: loading,
    error,
    refetch: loadStatus,
  } = useApi(
    () => tpm.getInfo(),
    [],
    {
      onError: (err) => {
        toast({
          title: "Error loading TPM status",
          description: err.message,
          variant: "destructive",
        });
      },
    }
  );

  // Helper to find capability by name
  const findCapability = (caps: Array<{ name: string; supported: boolean; value?: string }> | undefined, name: string) => {
    return caps?.find(c => c.name === name);
  };

  // Transform SDK data to local TPMStatus type
  const status: TPMStatus | null = React.useMemo(() => {
    if (!infoData) return null;
    const info = infoData;
    const caps = info.capabilities || [];
    return {
      available: true,
      enabled: true,
      activated: true,
      owned: findCapability(caps, 'ownershipEstablished')?.supported ?? false,
      info: {
        manufacturer: info.manufacturer?.name || "Unknown",
        manufacturerId: info.manufacturer?.id?.toString(16) || "0x00000000",
        vendorString: info.manufacturer?.model || "",
        specVersion: info.version?.replace('TPM_', '').replace('_', '.') || "2.0",
        specLevel: 0,
        specRevision: 0,
        firmwareVersion: info.manufacturer?.firmwareVersion || "",
        familyIndicator: info.version || "2.0",
        lockoutCounter: parseInt(findCapability(caps, 'lockoutCounter')?.value || "0"),
        lockoutRecovery: parseInt(findCapability(caps, 'lockoutRecovery')?.value || "0"),
        maxAuthFail: parseInt(findCapability(caps, 'maxAuthFail')?.value || "32"),
      },
      capabilities: {
        hasEK: findCapability(caps, 'hasEK')?.supported ?? false,
        hasSRK: findCapability(caps, 'hasSRK')?.supported ?? false,
        hasOwner: findCapability(caps, 'hasOwner')?.supported ?? false,
        ownerAuthSet: findCapability(caps, 'ownerAuthSet')?.supported ?? false,
        endorsementAuthSet: findCapability(caps, 'endorsementAuthSet')?.supported ?? false,
        lockoutAuthSet: findCapability(caps, 'lockoutAuthSet')?.supported ?? false,
        isPhysicalPresenceEnabled: findCapability(caps, 'physicalPresence')?.supported ?? false,
        isPlatformHierarchyEnabled: findCapability(caps, 'platformHierarchy')?.supported ?? true,
        isStorageHierarchyEnabled: findCapability(caps, 'storageHierarchy')?.supported ?? true,
        isEndorsementHierarchyEnabled: findCapability(caps, 'endorsementHierarchy')?.supported ?? true,
      },
    };
  }, [infoData]);

  const getStatusBadge = (enabled: boolean, label: string) => (
    <Badge variant={enabled ? "default" : "secondary"}>
      {enabled ? label : `Not ${label}`}
    </Badge>
  );

  if (loading && !status) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">TPM Status</h1>
            <p className="text-muted-foreground">
              View TPM module status and information
            </p>
          </div>
        </div>
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">TPM Status</h1>
          <p className="text-muted-foreground">
            View TPM module status and information
          </p>
        </div>
        <Button variant="outline" onClick={() => loadStatus()} disabled={loading}>
          <RefreshCw
            className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`}
          />
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

      {status && (
        <>
          {/* Overall Status Cards */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">TPM Status</CardTitle>
                <Shield className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2">
                  {status.available ? (
                    <ShieldCheck className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-destructive" />
                  )}
                  <span className="text-2xl font-bold">
                    {status.available ? "Available" : "Unavailable"}
                  </span>
                </div>
                <div className="flex gap-2 mt-2">
                  {getStatusBadge(status.enabled, "Enabled")}
                  {getStatusBadge(status.activated, "Activated")}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Manufacturer</CardTitle>
                <Cpu className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{status.info.manufacturer}</div>
                <p className="text-xs text-muted-foreground">
                  ID: {status.info.manufacturerId}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">TPM Version</CardTitle>
                <HardDrive className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">TPM {status.info.specVersion}</div>
                <p className="text-xs text-muted-foreground">
                  Firmware: {status.info.firmwareVersion}
                </p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">Ownership</CardTitle>
                <Key className="h-4 w-4 text-muted-foreground" />
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2">
                  {status.owned ? (
                    <ShieldCheck className="h-5 w-5 text-green-500" />
                  ) : (
                    <AlertCircle className="h-5 w-5 text-orange-500" />
                  )}
                  <span className="text-2xl font-bold">
                    {status.owned ? "Owned" : "Not Owned"}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  {status.owned ? "TPM is provisioned" : "TPM needs provisioning"}
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Detailed Information */}
          <div className="grid gap-6 md:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>TPM Information</CardTitle>
                <CardDescription>
                  Detailed TPM module specifications
                </CardDescription>
              </CardHeader>
              <CardContent>
                <dl className="space-y-3">
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Vendor String</dt>
                    <dd className="text-sm font-medium">{status.info.vendorString}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Spec Level</dt>
                    <dd className="text-sm font-medium">{status.info.specLevel}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Spec Revision</dt>
                    <dd className="text-sm font-medium">{status.info.specRevision}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Family Indicator</dt>
                    <dd className="text-sm font-medium">{status.info.familyIndicator}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Lockout Counter</dt>
                    <dd className="text-sm font-medium">{status.info.lockoutCounter}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Lockout Recovery (sec)</dt>
                    <dd className="text-sm font-medium">{status.info.lockoutRecovery}</dd>
                  </div>
                  <div className="flex justify-between">
                    <dt className="text-sm text-muted-foreground">Max Auth Failures</dt>
                    <dd className="text-sm font-medium">{status.info.maxAuthFail}</dd>
                  </div>
                </dl>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Capabilities</CardTitle>
                <CardDescription>
                  TPM capability and hierarchy status
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-medium mb-2">Key Presence</h4>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={status.capabilities.hasEK ? "default" : "secondary"}>
                        {status.capabilities.hasEK ? "EK Present" : "No EK"}
                      </Badge>
                      <Badge variant={status.capabilities.hasSRK ? "default" : "secondary"}>
                        {status.capabilities.hasSRK ? "SRK Present" : "No SRK"}
                      </Badge>
                      <Badge variant={status.capabilities.hasOwner ? "default" : "secondary"}>
                        {status.capabilities.hasOwner ? "Owner Set" : "No Owner"}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium mb-2">Authorization</h4>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={status.capabilities.ownerAuthSet ? "default" : "outline"}>
                        Owner Auth
                      </Badge>
                      <Badge variant={status.capabilities.endorsementAuthSet ? "default" : "outline"}>
                        Endorsement Auth
                      </Badge>
                      <Badge variant={status.capabilities.lockoutAuthSet ? "default" : "outline"}>
                        Lockout Auth
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium mb-2">Hierarchies</h4>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant={status.capabilities.isPlatformHierarchyEnabled ? "default" : "outline"}>
                        Platform
                      </Badge>
                      <Badge variant={status.capabilities.isStorageHierarchyEnabled ? "default" : "outline"}>
                        Storage
                      </Badge>
                      <Badge variant={status.capabilities.isEndorsementHierarchyEnabled ? "default" : "outline"}>
                        Endorsement
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h4 className="text-sm font-medium mb-2">Physical Presence</h4>
                    <Badge variant={status.capabilities.isPhysicalPresenceEnabled ? "default" : "outline"}>
                      {status.capabilities.isPhysicalPresenceEnabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
