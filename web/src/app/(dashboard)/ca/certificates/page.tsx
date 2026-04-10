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

  // Transform SDK CertificateSummary to local Certificate type
  const certificates: Certificate[] = React.useMemo(() => {
    const certs = certificatesResponse?.certificates ?? [];
    return certs.map((cert) => ({
      id: cert.serial,
      serialNumber: cert.serial,
      subject: cert.commonName || "Unknown",
      issuer: cert.issuer || "Unknown",
      type: "leaf" as const,
      status: cert.status === "REVOKED" ? "revoked" as const :
              cert.status === "EXPIRED" ? "expired" as const : "active" as const,
      notBefore: cert.notBefore || "",
      notAfter: cert.notAfter || "",
      publicKeyAlgorithm: cert.keyAlgorithm || "RSA_2048",
      signatureAlgorithm: "SHA256WithRSA",
    }));
  }, [certificatesResponse]);

  const error = fetchError?.message ?? null;

  // Map local key algorithm to SDK KeyAlgorithm
  const mapKeyAlgorithm = (algo: string): KeyAlgorithm => {
    const mapping: Record<string, KeyAlgorithm> = {
      "RSA-2048": "RSA_2048",
      "RSA-4096": "RSA_4096",
      "ECDSA-P256": "ECDSA_P256",
      "ECDSA-P384": "ECDSA_P384",
    };
    return mapping[algo] || "RSA_2048";
  };

  // Issue certificate mutation
  const issueCertMutation = useMutation(
    (data: IssueCertInput) => ca.issueCertificate({
      subject: {
        commonName: data.subject || "Unknown",
      },
      validDays: data.validityDays || 365,
      keyAlgorithm: mapKeyAlgorithm(data.keyAlgorithm),
    }),
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
