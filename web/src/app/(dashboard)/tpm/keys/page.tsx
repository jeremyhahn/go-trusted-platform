"use client";

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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  RefreshCw,
  Key,
  Shield,
  Lock,
  Fingerprint,
  AlertCircle,
  Eye,
  Copy,
  MoreHorizontal,
  Loader2,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useApi, useIDevID, useTPM, useToast } from "@/hooks";
import { TPMKeyOperations } from "./key-operations";
import type { KeyAlgorithm } from "trusted-platform-sdk";
import { errorMessage } from "@/utils/errors";

/**
 * TPM Key types — covers the full TCG-prescribed key inventory of a
 * provisioned trusted-platform node.
 *
 *   EK         — Endorsement Key (manufacturer identity)              0x81010001
 *   SSRK       — Storage hierarchy Storage Root Key                   0x81000001
 *   PSRK       — Platform hierarchy Storage Root Key                  0x81000002
 *   IAK        — Initial Attestation Key (TCG IAK)                    0x81010002
 *   IDevID     — Initial Device Identifier (TCG IDevID)               0x81020000
 *
 * "AK" was the legacy lump-sum label used before the dedicated
 * IAK/IDevID services landed. We keep it as an alias for IAK so
 * existing dropdown/badge components continue to compile, but the
 * row-rendering code drives off the explicit type names.
 */
type TPMKeyType = "EK" | "SRK" | "PSRK" | "AK" | "IAK" | "IDevID";
type TPMKeyStatus = "active" | "disabled" | "pending";

interface TPMKey {
  id: string;
  name: string;
  type: TPMKeyType;
  algorithm: KeyAlgorithm;
  status: TPMKeyStatus;
  handle: number;
  publicKey: string;
  createdAt: string;
  parentHandle?: string;
  certificatePresent?: boolean;
}

/**
 * Render a TPM-key createdAt timestamp. The backend does not yet expose
 * a creation timestamp for EK / SRK / PSRK (those are persisted in NV at
 * fixed handles and survive every restart), so the field is often empty.
 * Returning "—" is honest; falling back to `new Date()` would make every
 * key look like it was generated today on every page load.
 */
function formatCreatedAt(value: string | undefined | null): string {
  if (!value) return "—";
  const d = new Date(value);
  if (!Number.isFinite(d.getTime())) return "—";
  return d.toLocaleDateString();
}

/**
 * TPM Keys Management Page
 *
 * Features:
 * - View all TPM keys (EK, SRK, AK)
 * - Display key details and attributes
 * - Public key hash viewing
 */
// detailedKey carries everything the View Details dialog needs to
// display: the full public key (PEM, never just a hash), the X.509
// certificate chain when one exists, and the attestation flags
// reported by the server. Populated lazily when the operator
// clicks the View Details menu item — fetching certs eagerly for
// every refresh would force a TPM round-trip per key on every
// page mount.
interface DetailedKey {
  key: TPMKey;
  certificatePem: string | null;
  certificateLoading: boolean;
  certificateError: string | null;
}

export default function TPMKeysPage() {
  const { toast } = useToast();
  const tpm = useTPM();
  const idevid = useIDevID();
  const [detail, setDetail] = React.useState<DetailedKey | null>(null);

  // openDetail fetches the certificate (when this key type carries
  // one) and opens the modal. EK pulls from /tpm/ek/certificate; IAK
  // and IDevID pull from /idevid/iak/certificate and
  // /idevid/certificate respectively. SRK/PSRK do not carry x509
  // certificates by design (they're storage hierarchy primaries),
  // so we render their public key only.
  const openDetail = React.useCallback(
    async (key: TPMKey) => {
      setDetail({ key, certificatePem: null, certificateLoading: true, certificateError: null });
      try {
        let pem: string | null = null;
        if (key.type === "EK") {
          const resp = await tpm.getEKCertificate();
          pem = resp.data?.certificate ?? null;
        } else if (key.type === "IAK") {
          const resp = await idevid.getIAKCertificate();
          pem = resp.data?.certificate?.pem ?? null;
        } else if (key.type === "IDevID") {
          const resp = await idevid.getIDevIDCertificate();
          pem = resp.data?.certificate?.pem ?? null;
        }
        setDetail({ key, certificatePem: pem, certificateLoading: false, certificateError: null });
      } catch (err) {
        setDetail({
          key,
          certificatePem: null,
          certificateLoading: false,
          certificateError: errorMessage(err, "Failed to load certificate"),
        });
      }
    },
    [tpm, idevid],
  );

  const {
    data: ekData,
    isLoading: ekLoading,
    error: ekError,
    refetch: refetchEK,
  } = useApi(
    () => tpm.getEK().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  const {
    data: srkData,
    isLoading: srkLoading,
    error: srkError,
    refetch: refetchSRK,
  } = useApi(
    () => tpm.getSRK().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  // Fetch the PlatformSRK at handle 0x81000002 as a separate query.
  // The server's GetSRK handler now respects req.Handle (see
  // pkg/api/daemon/tpm_grpc_service.go::GetSRK), defaulting to the
  // SSRK (0x81000001) when unset for back-compat. Without this
  // second fetch the Keys page only shows 4 of 5 TCG-prescribed
  // handles.
  const {
    data: platformSRKData,
    isLoading: psrkLoading,
    error: psrkError,
    refetch: refetchPSRK,
  } = useApi(
    () =>
      tpm
        .getSRK({ handle: 0x81000002 })
        .catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  // Dedicated IAK fetch via the IDevIDService endpoint. This is the
  // canonical IAK info path — it returns the actual algorithm
  // (DEVICE_KEY_ALGORITHM_ECDSA_P256) and the certificate-present
  // flag. The legacy /tpm/ak endpoint reports the same persistent
  // handle (0x81010002) but with a stale algorithm label, so we
  // prefer this one.
  const {
    data: iakInfo,
    isLoading: iakLoading,
    error: iakError,
    refetch: refetchIAK,
  } = useApi(
    () => idevid.getIAKInfo().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  // IDevID via the IDevIDService. Without this the Keys page only
  // renders 3 of the 5 TCG-prescribed handles; production audits
  // expect to see the IDevID row.
  const {
    data: idevidInfo,
    isLoading: idevidLoading,
    error: idevidError,
    refetch: refetchIDevID,
  } = useApi(
    () => idevid.getIDevIDInfo().catch(() => ({ success: false, data: null })),
    [],
    { onError: () => {} }
  );

  const loading = ekLoading || srkLoading || psrkLoading || iakLoading || idevidLoading;
  const error = ekError || srkError || psrkError || iakError || idevidError;

  const keys: TPMKey[] = React.useMemo(() => {
    const result: TPMKey[] = [];

    // TPM keys are persisted in NV at fixed handles; they are created
    // once during platform provisioning and survive every subsequent
    // platformd restart. The backend currently doesn't surface a real
    // "created at" timestamp for EK / SRK / PSRK, so we leave the field
    // empty rather than fabricating `new Date()` and lying about it.
    // The UI renders an empty createdAt as "—". When the backend grows
    // a real timestamp we'll pick it up here without further changes.
    if (ekData?.publicKey) {
      result.push({
        id: "ek",
        name: "Endorsement Key",
        type: "EK",
        algorithm: ekData.algorithm,
        status: "active",
        handle: ekData.handle,
        publicKey: ekData.publicKey,
        createdAt: "",
      });
    }

    if (srkData?.publicKey) {
      result.push({
        id: "srk",
        name: "Storage Root Key (SSRK)",
        type: "SRK",
        algorithm: srkData.algorithm,
        status: "active",
        handle: srkData.handle,
        publicKey: srkData.publicKey,
        createdAt: "",
      });
    }

    if (platformSRKData?.publicKey) {
      result.push({
        id: "psrk",
        name: "Platform Storage Root Key (PSRK)",
        type: "PSRK",
        algorithm: platformSRKData.algorithm,
        status: "active",
        handle: platformSRKData.handle,
        publicKey: platformSRKData.publicKey,
        createdAt: "",
      });
    }

    // IAK row — surface algorithm + certificate-present flag from
    // the dedicated info struct rather than the legacy /tpm/ak path.
    const iak = iakInfo?.keyInfo;
    if (iak?.handle) {
      result.push({
        id: "iak",
        name: "Initial Attestation Key (IAK)",
        type: "IAK",
        algorithm: iak.algorithm,
        status: "active",
        handle: iak.handle,
        publicKey: iak.publicKeyPem || "",
        createdAt: iak.createdAt || "",
        certificatePresent: iak.hasCertificate === true,
      });
    }

    // IDevID row — same shape; reads from the IDevIDService.
    const idv = idevidInfo?.keyInfo;
    if (idv?.handle) {
      result.push({
        id: "idevid",
        name: "Initial Device Identifier (IDevID)",
        type: "IDevID",
        algorithm: idv.algorithm,
        status: "active",
        handle: idv.handle,
        publicKey: idv.publicKeyPem || "",
        createdAt: idv.createdAt || "",
        certificatePresent: idv.hasCertificate === true,
      });
    }

    return result;
  }, [ekData, srkData, platformSRKData, iakInfo, idevidInfo]);

  const handleRefresh = () => {
    refetchEK();
    refetchSRK();
    refetchPSRK();
    refetchIAK();
    refetchIDevID();
  };

  const getKeyTypeIcon = (type: TPMKeyType) => {
    switch (type) {
      case "EK":
        return <Fingerprint className="h-4 w-4" />;
      case "SRK":
      case "PSRK":
        return <Lock className="h-4 w-4" />;
      case "AK":
      case "IAK":
      case "IDevID":
        return <Shield className="h-4 w-4" />;
    }
  };

  const getKeyTypeBadgeVariant = (type: TPMKeyType): "default" | "secondary" | "outline" => {
    return "default";
  };

  const getStatusBadgeVariant = (status: TPMKeyStatus): "default" | "secondary" | "destructive" => {
    switch (status) {
      case "active":
        return "default";
      case "disabled":
        return "destructive";
      case "pending":
        return "secondary";
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to clipboard",
      description: "Public key has been copied to clipboard",
      variant: "success",
    });
  };

  const keyStats = React.useMemo(() => {
    return {
      total: keys.length,
      ek: keys.filter((k) => k.type === "EK").length,
      srk: keys.filter((k) => k.type === "SRK" || k.type === "PSRK").length,
      ak: keys.filter((k) => k.type === "AK" || k.type === "IAK").length,
      idevid: keys.filter((k) => k.type === "IDevID").length,
    };
  }, [keys]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">TPM Keys</h1>
          <p className="text-muted-foreground">
            Manage TPM cryptographic keys (EK, SRK, AK)
          </p>
        </div>
        <Button variant="outline" onClick={handleRefresh} disabled={loading}>
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

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Keys</CardTitle>
            <Key className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.total}</div>
            <p className="text-xs text-muted-foreground">of 5 expected</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Endorsement Key</CardTitle>
            <Fingerprint className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.ek}</div>
            <p className="text-xs text-muted-foreground">Device identity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Storage Root Key</CardTitle>
            <Lock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.srk}</div>
            <p className="text-xs text-muted-foreground">Key hierarchy root</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attestation Key</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.ak}</div>
            <p className="text-xs text-muted-foreground">TPM quotes (IAK)</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Device Identifier</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{keyStats.idevid}</div>
            <p className="text-xs text-muted-foreground">IDevID (TCG)</p>
          </CardContent>
        </Card>

      </div>

      {/* Keys Table */}
      <Card>
        <CardHeader>
          <CardTitle>Key Inventory</CardTitle>
          <CardDescription>
            All TPM-resident cryptographic keys
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              <span className="ml-2 text-muted-foreground">Loading keys...</span>
            </div>
          ) : keys.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No TPM keys found. Keys may need to be provisioned.
            </div>
          ) : (
            <div className="rounded-md border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Algorithm</TableHead>
                    <TableHead>Handle</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead className="w-12"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.map((key) => (
                    <TableRow key={key.id}>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          {getKeyTypeIcon(key.type)}
                          <div>
                            <div className="font-medium">{key.name}</div>
                            <code className="text-xs text-muted-foreground">
                              {key.publicKey.slice(0, 16)}...
                            </code>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getKeyTypeBadgeVariant(key.type)}>
                          {key.type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm">{key.algorithm}</span>
                      </TableCell>
                      <TableCell>
                        <code className="text-sm bg-muted px-2 py-1 rounded">
                          0x{key.handle.toString(16).toUpperCase().padStart(8, '0')}
                        </code>
                      </TableCell>
                      <TableCell>
                        <Badge variant={getStatusBadgeVariant(key.status)}>
                          {key.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <span className="text-sm text-muted-foreground">
                          {formatCreatedAt(key.createdAt)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => openDetail(key)}>
                              <Eye className="mr-2 h-4 w-4" />
                              View Details
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => copyToClipboard(key.publicKey)}
                            >
                              <Copy className="mr-2 h-4 w-4" />
                              Copy Public Key
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Key lifecycle operations (#1735) */}
      <TPMKeyOperations onChanged={handleRefresh} />

      {/* Key Hierarchy */}
      <Card>
        <CardHeader>
          <CardTitle>Key Hierarchy</CardTitle>
          <CardDescription>
            TPM key relationships and parent-child structure
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="text-sm text-muted-foreground">
              <p>
                The TPM maintains a key hierarchy where the Storage Root Key (SRK)
                serves as the parent for most user-created keys. The Endorsement Key
                (EK) is unique to each TPM and used for device identity, while
                Attestation Keys (AK) are used for signing TPM quotes.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {keys.map((key) => (
                <div
                  key={key.id}
                  className="flex items-center gap-1 text-xs bg-muted px-2 py-1 rounded"
                >
                  {getKeyTypeIcon(key.type)}
                  <span>{key.name}</span>
                  {key.parentHandle && key.parentHandle !== "0x40000001" && (
                    <span className="text-muted-foreground">
                      (parent: {key.parentHandle})
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Dialog open={detail !== null} onOpenChange={(o) => { if (!o) setDetail(null); }}>
        <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
          {detail && (
            <>
              <DialogHeader>
                <DialogTitle className="flex items-center gap-2">
                  {getKeyTypeIcon(detail.key.type)}
                  {detail.key.name}
                </DialogTitle>
                <DialogDescription>
                  Persistent handle <code className="font-mono">0x{detail.key.handle.toString(16).toUpperCase().padStart(8, "0")}</code> &middot; {detail.key.algorithm}
                </DialogDescription>
              </DialogHeader>

              <div className="space-y-5">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <div className="text-muted-foreground">Type</div>
                    <Badge variant="outline">{detail.key.type}</Badge>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Status</div>
                    <Badge variant={getStatusBadgeVariant(detail.key.status)}>{detail.key.status}</Badge>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Parent Handle</div>
                    <code className="font-mono text-xs">{detail.key.parentHandle || "—"}</code>
                  </div>
                  <div>
                    <div className="text-muted-foreground">Certificate</div>
                    <span className="text-xs">
                      {detail.key.certificatePresent === false
                        ? "not provisioned"
                        : detail.key.certificatePresent === true
                          ? "present"
                          : detail.key.type === "EK"
                            ? "manufacturer-issued"
                            : "—"}
                    </span>
                  </div>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium">Public Key (PEM)</span>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => copyToClipboard(detail.key.publicKey)}
                      disabled={!detail.key.publicKey}
                    >
                      <Copy className="h-3 w-3 mr-1" /> Copy
                    </Button>
                  </div>
                  <pre className="bg-muted p-3 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-48 overflow-y-auto">
                    {detail.key.publicKey || "(no public key surfaced)"}
                  </pre>
                </div>

                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium">X.509 Certificate</span>
                    {detail.certificatePem && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => copyToClipboard(detail.certificatePem || "")}
                      >
                        <Copy className="h-3 w-3 mr-1" /> Copy PEM
                      </Button>
                    )}
                  </div>
                  {detail.certificateLoading ? (
                    <div className="flex items-center gap-2 text-muted-foreground text-sm py-3">
                      <Loader2 className="h-4 w-4 animate-spin" /> Fetching certificate from TPM…
                    </div>
                  ) : detail.certificateError ? (
                    <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive rounded">
                      <AlertCircle className="h-4 w-4 text-destructive" />
                      <span className="text-xs text-destructive">{detail.certificateError}</span>
                    </div>
                  ) : detail.certificatePem ? (
                    <pre className="bg-muted p-3 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-72 overflow-y-auto">
                      {decodeCertificatePem(detail.certificatePem)}
                    </pre>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      No certificate is provisioned for this key.{" "}
                      {detail.key.type === "SRK" || detail.key.type === "PSRK"
                        ? "Storage hierarchy primaries do not carry x509 certificates."
                        : detail.key.type === "EK"
                          ? "Some TPMs ship with the EK cert in NV index 0x1c00002 — try Provision → Read NV."
                          : "Use the Issue Certificate flow to provision one."}
                    </p>
                  )}
                </div>
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

// decodeCertificatePem normalizes the certificate payload returned
// by the server. /tpm/ek/certificate returns raw DER (base64-
// encoded by protojson); /idevid/certificate returns either DER or
// already-PEM-wrapped depending on which endpoint variant the
// platform exposed. This helper detects and re-wraps DER into a
// proper PEM block so the dialog never displays unprintable bytes.
function decodeCertificatePem(payload: string): string {
  if (!payload) return "";
  if (payload.startsWith("-----BEGIN")) return payload;
  // Treat as base64-encoded DER and rewrap.
  const lines: string[] = [];
  for (let i = 0; i < payload.length; i += 64) {
    lines.push(payload.slice(i, i + 64));
  }
  return ["-----BEGIN CERTIFICATE-----", ...lines, "-----END CERTIFICATE-----"].join("\n");
}
