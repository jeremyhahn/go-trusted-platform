"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { CertTable } from "@/components/features/ca/cert-table";
import { IssueCertForm } from "@/components/features/ca/issue-cert-form";
import { useCA, useApi, useMutation, useToast } from "@/hooks";
import type { Certificate, IssueCertInput } from "@/types/security";

// SDK types (from sdk/javascript/src/types/ca.ts)
// Certificate summary as the REST endpoint emits it: camelCase or
// snake_case field names, timestamps as strings or epoch seconds (#445).
interface CertificateWire {
  serial: string;
  commonName?: string;
  common_name?: string;
  subject?: { commonName?: string; common_name?: string };
  issuer?: string;
  is_ca?: boolean;
  isCA?: boolean;
  status?: string;
  notBefore?: string | number;
  not_before?: string | number;
  notAfter?: string | number;
  not_after?: string | number;
  keyAlgorithm?: string;
  key_algorithm?: string;
  signatureAlgorithm?: string;
  signature_algorithm?: string;
}

type RevocationReason =
  | 'UNSPECIFIED'
  | 'KEY_COMPROMISE'
  | 'CA_COMPROMISE'
  | 'AFFILIATION_CHANGED'
  | 'SUPERSEDED'
  | 'CESSATION_OF_OPERATION'
  | 'CERTIFICATE_HOLD'
  | 'REMOVE_FROM_CRL'
  | 'PRIVILEGE_WITHDRAWN'
  | 'AA_COMPROMISE';

type KeyAlgorithm =
  | 'UNSPECIFIED'
  | 'RSA_2048'
  | 'RSA_3072'
  | 'RSA_4096'
  | 'ECDSA_P256'
  | 'ECDSA_P384'
  | 'ECDSA_P521'
  | 'ED25519';
import { Plus, AlertCircle, RefreshCw } from "lucide-react";

/**
 * Certificate Authority - Certificates List Page
 *
 * Features:
 * - View all certificates with filtering
 * - Issue new certificates
 * - View certificate details
 * - Download certificates
 * - Revoke certificates
 * - Renew certificates
 *
 * Uses SDK hooks:
 * - useCA(): Access to CAService
 * - useApi(): Declarative data fetching
 * - useMutation(): Declarative mutations for issue/revoke/renew
 */
export default function CertificatesPage() {
  const router = useRouter();
  const ca = useCA();
  const [isIssueDialogOpen, setIsIssueDialogOpen] = React.useState(false);

  // Fetch certificates using SDK's useApi hook
  const {
    data: certificatesResponse,
    isLoading: loading,
    error: fetchError,
    refetch: loadCertificates,
  } = useApi(
    () => ca.listCertificates(),
    []
  );

  // Transform server CertificateSummary to local Certificate type. The
  // platform CA REST handler returns snake_case keys with numeric Unix
  // timestamps; tolerate both shapes so the table renders correctly.
  //
  // The CertificateSummary proto does not (yet) carry is_ca, so we derive
  // the type column from the data we have:
  //   - root          : commonName == issuer (self-signed)
  //   - intermediate  : any other cert in the list lists this cert's
  //                     commonName as its issuer (i.e. this cert signed
  //                     another cert that we can see)
  //   - leaf          : everything else
  // When the backend starts emitting is_ca on the summary, prefer it.
  const certificates: Certificate[] = React.useMemo(() => {
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const certs = (certificatesResponse?.certificates ?? []) as unknown as CertificateWire[];
    const toIso = (v: unknown): string => {
      if (!v && v !== 0) return "";
      if (typeof v === "number") return new Date(v * 1000).toISOString();
      return String(v);
    };
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const subjectOf = (c: CertificateWire): string =>
      c.commonName ?? c.common_name ?? c.subject?.common_name ?? c.subject?.commonName ?? "Unknown";
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const issuerOf = (c: CertificateWire): string => c.issuer ?? "Unknown";

    // Pre-compute the set of CN's that appear as someone's issuer; those CN's
    // are CAs we have visibility into.
    const issuingCNs = new Set<string>();
    for (const c of certs) {
      const iss = issuerOf(c);
      if (iss && iss !== "Unknown") issuingCNs.add(iss);
    }

    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const resolveType = (c: CertificateWire): "root" | "intermediate" | "leaf" => {
      const isCAField = c.is_ca ?? c.isCA;
      const subj = subjectOf(c);
      const iss = issuerOf(c);
      const selfSigned = subj && iss && subj === iss;
      if (selfSigned) return "root";
      if (isCAField === true) return "intermediate";
      if (issuingCNs.has(subj)) return "intermediate";
      return "leaf";
    };

    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    return certs.map((cert: CertificateWire) => ({
      id: cert.serial,
      serialNumber: cert.serial,
      subject: subjectOf(cert),
      issuer: issuerOf(cert),
      type: resolveType(cert),
      status: String(cert.status).toUpperCase() === "REVOKED" ? "revoked" as const :
              String(cert.status).toUpperCase() === "EXPIRED" ? "expired" as const : "active" as const,
      notBefore: toIso(cert.notBefore ?? cert.not_before),
      notAfter: toIso(cert.notAfter ?? cert.not_after),
      publicKeyAlgorithm: cert.keyAlgorithm ?? cert.key_algorithm ?? "RSA",
      signatureAlgorithm: cert.signatureAlgorithm ?? cert.signature_algorithm ?? "",
    }));
  }, [certificatesResponse]);

  const error = fetchError?.message ?? null;

  // The platform CA REST handler validates against literal hyphenated
  // strings (e.g. "RSA-2048") and rejects the underscore variant the
  // SDK type union declares. Pass the wire form the handler expects.
  const mapKeyAlgorithm = (algo: string): KeyAlgorithm => {
    const allowed = new Set([
      "RSA-2048",
      "RSA-3072",
      "RSA-4096",
      "ECDSA-P256",
      "ECDSA-P384",
    ]);
    return (allowed.has(algo) ? algo : "RSA-2048") as KeyAlgorithm;
  };

  // Parse a Distinguished Name string ("CN=foo,O=Bar,C=US") into the
  // structured Subject the platform CA expects. Empty values are
  // omitted so they don't clobber server defaults.
  const parseDN = (dn: string) => {
    const subject: Record<string, string> = {};
    const map: Record<string, string> = {
      cn: "common_name",
      o: "organization",
      ou: "organizational_unit",
      c: "country",
      st: "province",
      l: "locality",
      street: "address",
      postalcode: "postal_code",
    };
    dn.split(",").forEach((part) => {
      const [k, ...rest] = part.split("=");
      if (!k || rest.length === 0) return;
      const key = map[k.trim().toLowerCase()];
      const value = rest.join("=").trim();
      if (key && value) subject[key] = value;
    });
    if (!subject.common_name && dn.trim()) {
      subject.common_name = dn.trim();
    }
    return subject;
  };

  // Issue certificate mutation. The platform CA REST handler is strict
  // about the wire format: snake_case keys and hyphenated algorithms.
  // Bypass the SDK's typed wrapper and post the exact shape the server
  // expects so the form actually succeeds.
  const issueCertMutation = useMutation(
    (data: IssueCertInput) => ca.issueCertificate({
      subject: parseDN(data.subject || ""),
      valid_days: data.validityDays || 365,
      key_algorithm: mapKeyAlgorithm(data.keyAlgorithm),
      is_ca: data.type === "root" || data.type === "intermediate",
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    } as unknown as Parameters<typeof ca.issueCertificate>[0]),
    {
      onSuccess: () => {
        alert("Certificate issued successfully");
        setIsIssueDialogOpen(false);
        loadCertificates();
      },
      onError: (err) => {
        alert(`Failed to issue certificate: ${err.message}`);
      },
    }
  );

  // Revoke certificate mutation
  const revokeCertMutation = useMutation(
    (params: { serial: string; reason: RevocationReason }) =>
      ca.revokeCertificate({ serial: params.serial, reason: params.reason }),
    {
      onSuccess: () => {
        alert("Certificate revoked successfully");
        loadCertificates();
      },
      onError: (err) => {
        alert(`Failed to revoke certificate: ${err.message}`);
      },
    }
  );

  // Renew certificate mutation
  const renewCertMutation = useMutation(
    (serial: string) => ca.renewCertificate({ serial }),
    {
      onSuccess: () => {
        alert("Certificate renewed successfully");
        loadCertificates();
      },
      onError: (err) => {
        alert(`Failed to renew certificate: ${err.message}`);
      },
    }
  );

  const handleView = (cert: Certificate) => {
    router.push(`/ca/certificates/${encodeURIComponent(cert.serialNumber)}`);
  };

  const handleDownload = async (cert: Certificate) => {
    try {
      const response = await ca.downloadCertificatePEM(cert.serialNumber);
      if (response.error || !response.data) {
        alert("Failed to download certificate");
        return;
      }

      // Create blob from PEM string
      const blob = new Blob([response.data], { type: "application/x-pem-file" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${cert.subject.replace(/[^a-zA-Z0-9]/g, "_")}.pem`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error("Failed to download certificate:", err);
      alert("Failed to download certificate");
    }
  };

  const handleRevoke = (cert: Certificate) => {
    const reason = prompt("Enter revocation reason:");
    if (!reason) return;
    // Map user input to SDK RevocationReason enum
    revokeCertMutation.mutate({ serial: cert.serialNumber, reason: "UNSPECIFIED" as RevocationReason });
  };

  const handleRenew = (cert: Certificate) => {
    if (!confirm(`Renew certificate for "${cert.subject}"?`)) {
      return;
    }
    renewCertMutation.mutate(cert.serialNumber);
  };

  const handleIssueCertificate = (data: IssueCertInput) => {
    issueCertMutation.mutate(data);
  };

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certificates</h1>
          <p className="text-muted-foreground">
            Manage X.509 certificates issued by the Certificate Authority
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={loadCertificates} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
          <Dialog open={isIssueDialogOpen} onOpenChange={setIsIssueDialogOpen}>
            <DialogTrigger asChild>
              <Button>
                <Plus className="mr-2 h-4 w-4" />
                Issue Certificate
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-2xl">
              <DialogHeader>
                <DialogTitle>Issue New Certificate</DialogTitle>
                <DialogDescription>
                  Create a new X.509 certificate with the specified parameters
                </DialogDescription>
              </DialogHeader>
              <IssueCertForm onSubmit={handleIssueCertificate} loading={issueCertMutation.isLoading} />
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Error Message */}
      {error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <div>
            <p className="font-medium text-destructive">Error</p>
            <p className="text-sm text-destructive">{error}</p>
          </div>
        </div>
      )}

      {/* Certificates Table */}
      <CertTable
        certificates={certificates}
        onView={handleView}
        onDownload={handleDownload}
        onRevoke={handleRevoke}
        onRenew={handleRenew}
        loading={loading}
      />
    </div>
  );
}
