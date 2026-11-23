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
import { Gated } from "@/components/features/capabilities/gated";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  RefreshCw,
  Shield,
  ShieldCheck,
  Cpu,
  HardDrive,
  Key,
  AlertCircle,
} from "lucide-react";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useTPM, useIDevID, useApi, useToast } from "@/hooks";
import { useIDevIDCerts, looksLikePem } from "@/hooks/use-idevid-certs";
import type {
  ApiResponse,
  GetEKResponse,
  GetIAKInfoResponse,
  GetSRKResponse,
  TPMCapability,
  TPMVersion,
} from "trusted-platform-sdk";

/** Display form of the server's TPMVersion enum; unspecified has none. */
const SPEC_VERSION: Record<TPMVersion, string | undefined> = {
  TPM_VERSION_UNSPECIFIED: undefined,
  TPM_VERSION_1_2: "1.2",
  TPM_VERSION_2_0: "2.0",
};

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
  const idevid = useIDevID();

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

  // Drive Capabilities-panel flags off real handle presence rather
  // than the server-reported `capabilities` array, which currently
  // ships as `[]` from /api/v1/tpm/info — the previous `findCapability(caps, 'hasEK')`
  // path always evaluated to `false` and rendered "No EK / No SRK /
  // No Owner" badges on a fully-provisioned TPM. Each fetch is
  // tolerant: a 404 / empty body simply means the corresponding key
  // isn't yet provisioned. We keep the four lookups parallel so a
  // single slow endpoint doesn't stall the page.
  const { data: ekProbe, refetch: refetchEK } = useApi(
    () => tpm.getEK().catch((): ApiResponse<GetEKResponse> => ({ success: false })),
    [],
    { onError: () => {} }
  );
  const { data: srkProbe, refetch: refetchSRK } = useApi(
    () => tpm.getSRK().catch((): ApiResponse<GetSRKResponse> => ({ success: false })),
    [],
    { onError: () => {} }
  );
  const { data: iakProbe, refetch: refetchIAK } = useApi(
    () => idevid.getIAKInfo().catch((): ApiResponse<GetIAKInfoResponse> => ({ success: false })),
    [],
    { onError: () => {} }
  );
  // HasIDevID / HasIAK answer presence directly. useApi keeps the last data
  // when a fetch fails, so a set error means the current answer is unknown,
  // whatever an earlier check said (#2170 Codex).
  const { data: idevidExists, error: idevidExistsError, refetch: refetchIDevID } = useApi(
    () => idevid.hasIDevID(),
    [],
    { onError: () => {} }
  );
  const { data: iakExists, error: iakExistsError, refetch: refetchIAKExists } = useApi(
    () => idevid.hasIAK(),
    [],
    { onError: () => {} }
  );
  const {
    data: deviceAttributes,
    error: deviceAttributesError,
    refetch: refetchAttributes,
  } = useApi(() => idevid.getDeviceAttributes(), [], { onError: () => {} });

  const refetchAll = React.useCallback(() => {
    loadStatus();
    refetchEK();
    refetchSRK();
    refetchIAK();
    refetchIDevID();
    refetchIAKExists();
    refetchAttributes();
  }, [loadStatus, refetchEK, refetchSRK, refetchIAK, refetchIDevID, refetchIAKExists, refetchAttributes]);

  // GenerateIAK / DeleteIAK: each call re-reads HasIAK and the IAK info
  // afterwards, whether it was accepted or refused (a refused GenerateIAK can
  // still leave an IAK). The buttons stay disabled until both reads answer, so
  // nobody acts on a stale badge (#2186 Codex). The SDK does not throw; a
  // refusal comes back as res.error, and useApi's refetch never rejects.
  const [iakBusy, setIakBusy] = React.useState(false);
  const [confirmDeleteIAK, setConfirmDeleteIAK] = React.useState(false);

  const rereadIAK = React.useCallback(
    () => Promise.all([refetchIAKExists(), refetchIAK()]),
    [refetchIAKExists, refetchIAK]
  );

  const generateIAK = React.useCallback(async () => {
    setIakBusy(true);
    try {
      const res = await idevid.generateIAK();
      if (res.error) {
        toast({ title: "IAK generation failed", description: res.error.message, variant: "destructive" });
      } else {
        toast({ title: "IAK generated", description: res.data?.status?.message || "The IAK was created" });
      }
    } finally {
      await rereadIAK();
      setIakBusy(false);
    }
  }, [idevid, toast, rereadIAK]);

  const deleteIAK = React.useCallback(async () => {
    setConfirmDeleteIAK(false);
    setIakBusy(true);
    try {
      const res = await idevid.deleteIAK();
      if (res.error) {
        toast({ title: "IAK delete refused", description: res.error.message, variant: "destructive" });
      } else {
        toast({ title: "IAK deleted", description: res.data?.status?.message || "The IAK was deleted" });
      }
    } finally {
      await rereadIAK();
      setIakBusy(false);
    }
  }, [idevid, toast, rereadIAK]);

  // FlushTransientContexts: flushes every transient TPM context. The SDK does
  // not throw; a refusal comes back as res.error.
  const [flushBusy, setFlushBusy] = React.useState(false);
  const [confirmFlush, setConfirmFlush] = React.useState(false);

  const flushContexts = React.useCallback(async () => {
    setConfirmFlush(false);
    setFlushBusy(true);
    try {
      const res = await idevid.flushTransientContexts();
      if (res.error) {
        toast({ title: "Flush refused", description: res.error.message, variant: "destructive" });
      } else {
        toast({
          title: "Transient contexts flushed",
          description: res.data?.status?.message || "The transient contexts were flushed",
        });
      }
    } finally {
      setFlushBusy(false);
    }
  }, [idevid, toast]);

  // InstallIDevIDCertificate / InstallIAKCertificate / DeleteIAKCertificate
  // through useIDevIDCerts (#2055). The SDK does not throw; a refusal comes
  // back as res.error and shows the server's message. The IAK CSR control is
  // deferred: the daemon's CreateIAKCSR (pkg/api/daemon/idevid_grpc_service.go)
  // cannot yet return a usable PEM CSR.
  const certs = useIDevIDCerts();
  const [idevidCertText, setIdevidCertText] = React.useState("");
  const [iakCertText, setIakCertText] = React.useState("");
  const [certBusy, setCertBusy] = React.useState(false);
  const [confirmDeleteIAKCert, setConfirmDeleteIAKCert] = React.useState(false);

  const installIDevIDCert = React.useCallback(async () => {
    setCertBusy(true);
    try {
      const res = await certs.installIDevIDCertificate(idevidCertText);
      if (res.error) {
        toast({ title: "IDevID certificate install refused", description: res.error.message, variant: "destructive" });
      } else {
        toast({
          title: "IDevID certificate installed",
          description: res.data?.status?.message || "The IDevID certificate was installed",
        });
      }
    } finally {
      setCertBusy(false);
    }
  }, [certs, idevidCertText, toast]);

  const installIAKCert = React.useCallback(async () => {
    setCertBusy(true);
    try {
      const res = await certs.installIAKCertificate(iakCertText);
      if (res.error) {
        toast({ title: "IAK certificate install refused", description: res.error.message, variant: "destructive" });
      } else {
        toast({
          title: "IAK certificate installed",
          description: res.data?.status?.message || "The IAK certificate was installed",
        });
      }
    } finally {
      setCertBusy(false);
    }
  }, [certs, iakCertText, toast]);

  const deleteIAKCert = React.useCallback(async () => {
    setConfirmDeleteIAKCert(false);
    setCertBusy(true);
    try {
      const res = await certs.deleteIAKCertificate();
      if (res.error) {
        toast({ title: "IAK certificate delete refused", description: res.error.message, variant: "destructive" });
      } else {
        toast({
          title: "IAK certificate deleted",
          description: res.data?.status?.message || "The IAK certificate was deleted",
        });
      }
    } finally {
      setCertBusy(false);
    }
  }, [certs, toast]);

  // Helper to find capability by name
  const findCapability = (caps: TPMCapability[] | undefined, name: string) => {
    return caps?.find(c => c.name === name);
  };

  // The platformd `/api/v1/tpm/info` endpoint emits structured fields
  // for `version`, `capabilities`, `pcrBanks` and `manufacturer`, plus
  // the free-form tpm2-tools `properties-fixed` text in `properties.info`.
  // `manufacturer` is null when the TPM's fixed properties cannot be
  // read, so parse the text blob as a fallback for the display fields.
  const parsePropertyBlob = (blob: string): Record<string, string> => {
    const out: Record<string, string> = {};
    if (!blob) return out;
    blob.split('\n').forEach((line) => {
      const m = line.match(/^\s*([A-Za-z0-9 .\-]+?):\s*(.+?)\s*$/);
      if (m) out[m[1].trim()] = m[2].trim();
    });
    return out;
  };

  // Transform SDK data to local TPMStatus type
  const status: TPMStatus | null = React.useMemo(() => {
    if (!infoData) return null;
    const info = infoData;
    const caps = info.capabilities;
    const props = parsePropertyBlob(info.properties?.info || '');
    return {
      available: true,
      enabled: true,
      activated: true,
      // Treat "owned" as "platform has minimum-viable provisioning":
      // EK + a storage hierarchy SRK both present. The capabilities
      // array is currently empty from the server, so the previous
      // `findCapability(caps, 'ownershipEstablished')` always
      // resolved false on a fully-provisioned TPM — the badge said
      // "Not Owned / TPM needs provisioning" while EK + SRK + IAK
      // were all resident at their TCG handles. Driving off real
      // probe data fixes that.
      owned:
        (!!ekProbe?.publicKey && !!srkProbe?.publicKey) ||
        (findCapability(caps, 'ownershipEstablished')?.supported ?? false),
      info: {
        manufacturer: info.manufacturer?.name || props['Manufacturer'] || 'Unknown',
        manufacturerId: info.manufacturer?.id?.toString?.(16) || props['Vendor ID'] || '—',
        vendorString: info.manufacturer?.model || props['Model'] || props['Vendor ID'] || '',
        specVersion: props['Family'] || SPEC_VERSION[info.version] || '2.0',
        specLevel: parseInt(props['Level'] || '0', 10),
        specRevision: parseFloat(props['Revision'] || '0') || 0,
        firmwareVersion: info.manufacturer?.firmwareVersion || props['Firmware'] || '',
        familyIndicator: props['Family'] || SPEC_VERSION[info.version] || '2.0',
        lockoutCounter: parseInt(props['Lockout Counter'] || findCapability(caps, 'lockoutCounter')?.value || '0', 10),
        lockoutRecovery: parseInt(props['Lockout Recovery'] || findCapability(caps, 'lockoutRecovery')?.value || '0', 10),
        maxAuthFail: parseInt(props['Max Auth Failures'] || findCapability(caps, 'maxAuthFail')?.value || '32', 10),
      },
      capabilities: {
        // Real handle presence — see the parallel fetches in the
        // component body. The legacy `findCapability(caps, 'hasEK')`
        // path is kept as a fallback for hypothetical future server
        // builds that DO populate the capabilities array, but the
        // primary signal is "did the dedicated endpoint return a
        // payload?".
        hasEK: !!ekProbe?.publicKey || (findCapability(caps, 'hasEK')?.supported ?? false),
        hasSRK: !!srkProbe?.publicKey || (findCapability(caps, 'hasSRK')?.supported ?? false),
        // "Owner" in TPM 2.0 means the OWNER hierarchy has an auth
        // value set; an EK + SRK + IAK trio always implies an
        // owner-equivalent provisioning event. Any of those keys
        // existing satisfies the "ownership established" predicate
        // for display purposes.
        hasOwner: !!ekProbe?.publicKey || !!srkProbe?.publicKey ||
                  !!iakProbe?.keyInfo || (findCapability(caps, 'hasOwner')?.supported ?? false),
        ownerAuthSet: findCapability(caps, 'ownerAuthSet')?.supported ?? !!srkProbe?.publicKey,
        endorsementAuthSet: findCapability(caps, 'endorsementAuthSet')?.supported ?? !!ekProbe?.publicKey,
        lockoutAuthSet: findCapability(caps, 'lockoutAuthSet')?.supported ?? false,
        isPhysicalPresenceEnabled: findCapability(caps, 'physicalPresence')?.supported ?? false,
        isPlatformHierarchyEnabled: findCapability(caps, 'platformHierarchy')?.supported ?? true,
        isStorageHierarchyEnabled: findCapability(caps, 'storageHierarchy')?.supported ?? true,
        isEndorsementHierarchyEnabled: findCapability(caps, 'endorsementHierarchy')?.supported ?? true,
      },
    };
  }, [infoData, ekProbe, srkProbe, iakProbe]);

  const getStatusBadge = (enabled: boolean, label: string) => (
    <Badge variant={enabled ? "default" : "secondary"}>
      {enabled ? label : `Not ${label}`}
    </Badge>
  );

  // Presence from HasIDevID / HasIAK: undefined means the check was
  // refused or failed, now or on the latest refresh, which is not the
  // same as "not provisioned".
  const presenceBadge = (exists: boolean | undefined, label: string) => {
    if (exists === true) return <Badge variant="default">{label} Present</Badge>;
    if (exists === false) return <Badge variant="secondary">No {label}</Badge>;
    return <Badge variant="outline">{label} Unknown</Badge>;
  };

  const attributes = deviceAttributes?.attributes;
  const attributeRows: Array<[string, string | undefined]> = [
    ["TPM Manufacturer", attributes?.tpmManufacturer],
    ["TPM Model", attributes?.tpmModel],
    ["TPM Version", attributes?.tpmVersion],
    ["Platform Manufacturer", attributes?.platformManufacturer],
    ["Platform Model", attributes?.platformModel],
    ["Platform Version", attributes?.platformVersion],
    ["Platform Serial", attributes?.platformSerial],
  ];

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
        <Button variant="outline" onClick={() => refetchAll()} disabled={loading}>
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
                      {presenceBadge(iakExistsError ? undefined : iakExists?.exists, "IAK")}
                      {presenceBadge(idevidExistsError ? undefined : idevidExists?.exists, "IDevID")}
                      <Badge variant={status.capabilities.hasOwner ? "default" : "secondary"}>
                        {status.capabilities.hasOwner ? "Owner Set" : "No Owner"}
                      </Badge>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-2" data-testid="iak-actions">
                      <Gated op="POST /api/v1/idevid/iak/generate">
                        <Button size="sm" variant="outline" onClick={() => void generateIAK()} disabled={iakBusy}>
                          Generate IAK
                        </Button>
                      </Gated>
                      <Gated op="DELETE /api/v1/idevid/iak">
                        <Button size="sm" variant="destructive" onClick={() => setConfirmDeleteIAK(true)} disabled={iakBusy}>
                          Delete IAK
                        </Button>
                      </Gated>
                    </div>
                    <div className="flex flex-wrap gap-2 mt-2" data-testid="tpm-maintenance">
                      <Gated op="POST /api/v1/idevid/flush">
                        <Button size="sm" variant="outline" onClick={() => setConfirmFlush(true)} disabled={flushBusy}>
                          Flush transient contexts
                        </Button>
                      </Gated>
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

            <Card data-testid="device-attributes">
              <CardHeader>
                <CardTitle>Device Attributes</CardTitle>
                <CardDescription>
                  TCG device attributes reported by the IDevID service
                </CardDescription>
              </CardHeader>
              <CardContent>
                {deviceAttributesError ? (
                  <p className="text-sm text-destructive">
                    Device attributes unavailable: {deviceAttributesError.message}
                  </p>
                ) : (
                  <dl className="space-y-3">
                    {attributeRows.map(([label, value]) => (
                      <div key={label} className="flex justify-between">
                        <dt className="text-sm text-muted-foreground">{label}</dt>
                        <dd className="text-sm font-medium">{value || "—"}</dd>
                      </div>
                    ))}
                  </dl>
                )}
              </CardContent>
            </Card>

            <Card data-testid="identity-certificates">
              <CardHeader>
                <CardTitle>Identity Certificates</CardTitle>
                <CardDescription>
                  IDevID / IAK certificate install through the IDevID service
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="idevid-cert-pem">IDevID certificate PEM</Label>
                    <Textarea
                      id="idevid-cert-pem"
                      value={idevidCertText}
                      onChange={(e) => setIdevidCertText(e.target.value)}
                    />
                    <Gated op="POST /api/v1/idevid/certificate">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void installIDevIDCert()}
                        disabled={certBusy || !looksLikePem(idevidCertText, "CERTIFICATE")}
                      >
                        Install IDevID certificate
                      </Button>
                    </Gated>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="iak-cert-pem">IAK certificate PEM</Label>
                    <Textarea
                      id="iak-cert-pem"
                      value={iakCertText}
                      onChange={(e) => setIakCertText(e.target.value)}
                    />
                    <Gated op="POST /api/v1/idevid/iak/certificate">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void installIAKCert()}
                        disabled={certBusy || !looksLikePem(iakCertText, "CERTIFICATE")}
                      >
                        Install IAK certificate
                      </Button>
                    </Gated>
                  </div>
                  <Gated op="DELETE /api/v1/idevid/iak/certificate">
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => setConfirmDeleteIAKCert(true)}
                      disabled={certBusy}
                    >
                      Delete IAK certificate
                    </Button>
                  </Gated>
                </div>
              </CardContent>
            </Card>
          </div>

          <Dialog open={confirmDeleteIAK} onOpenChange={setConfirmDeleteIAK}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Delete the IAK?</DialogTitle>
                <DialogDescription>
                  The IDevID service is asked to delete the Initial Attestation Key. The service may refuse: a TPM-resident IAK is not evicted by it.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setConfirmDeleteIAK(false)}>Cancel</Button>
                <Button type="button" variant="destructive" onClick={() => void deleteIAK()}>Delete IAK</Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Dialog open={confirmFlush} onOpenChange={setConfirmFlush}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Flush the transient contexts?</DialogTitle>
                <DialogDescription>
                  Every transient object and session loaded in the TPM is flushed. Persistent keys are not touched.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setConfirmFlush(false)}>
                  Cancel
                </Button>
                <Button type="button" onClick={() => void flushContexts()}>
                  Flush
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Dialog open={confirmDeleteIAKCert} onOpenChange={setConfirmDeleteIAKCert}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Delete the IAK certificate?</DialogTitle>
                <DialogDescription>
                  The IDevID service removes the installed IAK certificate. This cannot be undone.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={() => setConfirmDeleteIAKCert(false)}>
                  Cancel
                </Button>
                <Button type="button" variant="destructive" onClick={() => void deleteIAKCert()}>
                  Delete certificate
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </>
      )}
    </div>
  );
}
