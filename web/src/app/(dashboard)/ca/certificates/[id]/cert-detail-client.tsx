"use client";

import * as React from "react";
import { use } from "react";
import { usePathname, useRouter } from "next/navigation";
import { resolveDynamicId } from "@/utils/dynamic-route";
import { Button } from "@/components/ui/button";
import { CertDetail } from "@/components/features/ca/cert-detail";
import { CertChain } from "@/components/features/ca/cert-chain";
import { useCA, useApi, useMutation, useToast } from "@/hooks";
import type { RevocationReason } from "trusted-platform-sdk";
import type { CertificateDetail } from "@/types/security";
import { ArrowLeft, Loader2, AlertCircle } from "lucide-react";

/**
 * Certificate Detail Page
 *
 * Features:
 * - View complete certificate details
 * - Display certificate chain
 * - Download certificate in PEM/DER format
 * - Revoke certificate
 */
// The SDK enum, spelled out once so the prompt and the guard cannot drift.
const REVOCATION_REASONS = [
  "UNSPECIFIED", "KEY_COMPROMISE", "CA_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED",
  "CESSATION_OF_OPERATION", "CERTIFICATE_HOLD", "REMOVE_FROM_CRL", "PRIVILEGE_WITHDRAWN", "AA_COMPROMISE",
] as const satisfies readonly RevocationReason[];

function isRevocationReason(value: string): value is RevocationReason {
  return (REVOCATION_REASONS as readonly string[]).includes(value);
}

// The certificate as the platform CA REST handler returns it: snake_case
// or camelCase keys and Unix-second timestamps, which differs from the
// SDK/proto declaration (#445).
interface CertificateSubjectWire {
  commonName?: string;
  common_name?: string;
  organization?: string;
  O?: string;
  country?: string;
  C?: string;
}

interface CertificateWire {
  serial?: string;
  issuer?: string;
  status?: string;
  Status?: string;
  isCA?: boolean;
  is_ca?: boolean;
  subject?: CertificateSubjectWire;
  notBefore?: string | number;
  not_before?: string | number;
  notAfter?: string | number;
  not_after?: string | number;
  keyAlgorithm?: string;
  key_algorithm?: string;
  signatureAlgorithm?: string;
  signature_algorithm?: string;
  pem?: string;
  der?: string;
}

// The response either wraps the certificate at `.certificate` or is it.
interface CertificateResponseWire extends CertificateWire {
  certificate?: CertificateWire;
}

export default function CertificateDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const resolved = use(params);
  const pathname = usePathname();
  const id = resolveDynamicId(resolved, pathname, "certificates");
  const router = useRouter();
  const ca = useCA();
  const { toast } = useToast();

  // SDK getCertificate takes serial number as a string parameter
  const { data: response, isLoading: loading, error, refetch } = useApi(
    () => ca.getCertificate(id),
    [id]
  );

  // Transform SDK Certificate to UI CertificateDetail type. The platform
  // CA REST handler returns the certificate either at `.certificate`
  // (envelope) or directly on the payload, with snake_case keys and
  // numeric Unix-second timestamps. Tolerate both shapes and convert.
  const certificate = React.useMemo(() => {
    const wire = response as unknown as CertificateResponseWire | null | undefined;
    const cert: CertificateWire | null = wire?.certificate ?? wire ?? null;
    if (!cert) return null;

    const status: string = cert.status ?? cert.Status ?? 'VALID';
    const mapStatus = (s: string): 'active' | 'revoked' | 'expired' => {
      const u = String(s).toUpperCase();
      if (u === 'REVOKED') return 'revoked';
      if (u === 'EXPIRED') return 'expired';
      return 'active';
    };

    const isCA: boolean = cert.isCA ?? cert.is_ca ?? false;
    const mapType = (b: boolean): 'root' | 'intermediate' | 'leaf' => (b ? 'intermediate' : 'leaf');

    const subj: CertificateSubjectWire = cert.subject || {};
    const subjectCN: string = subj.commonName ?? subj.common_name ?? '';
    const subjectParts = [
      subjectCN ? `CN=${subjectCN}` : '',
      (subj.organization ?? subj.O) ? `O=${subj.organization ?? subj.O}` : '',
      (subj.country ?? subj.C) ? `C=${subj.country ?? subj.C}` : '',
    ].filter(Boolean).join(', ');

    const toIso = (v: unknown): string => {
      if (!v && v !== 0) return '';
      if (typeof v === 'number') {
        // Server sends Unix seconds; JS Date wants ms.
        return new Date(v * 1000).toISOString();
      }
      return String(v);
    };

    return {
      id: cert.serial,
      subject: subjectParts || subjectCN,
      issuer: cert.issuer,
      serialNumber: cert.serial,
      type: mapType(isCA),
      status: mapStatus(status),
      notBefore: toIso(cert.notBefore ?? cert.not_before),
      notAfter: toIso(cert.notAfter ?? cert.not_after),
      publicKeyAlgorithm: cert.keyAlgorithm ?? cert.key_algorithm ?? '',
      signatureAlgorithm: cert.signatureAlgorithm ?? cert.signature_algorithm ?? '',
      publicKey: '',
      extensions: [],
      chain: [],
      pemEncoded: cert.pem || '',
      derEncoded: cert.der || '',
    } as CertificateDetail;
  }, [response]);

  const revokeMutation = useMutation(
    (reason: RevocationReason) => ca.revokeCertificate({
      serial: id,
      reason,
    }),
    {
      onSuccess: () => {
        toast({
          title: "Success",
          description: "Certificate revoked successfully",
        });
        refetch();
      },
      onError: (error) => {
        toast({
          title: "Error",
          description: error.message,
          variant: "destructive",
        });
      },
    }
  );

  const handleDownloadPEM = async () => {
    if (!certificate) return;

    try {
      const pemData = certificate.pemEncoded;
      if (!pemData) {
        toast({
          title: "Error",
          description: "Certificate data not available",
          variant: "destructive",
        });
        return;
      }

      const blob = new Blob([pemData], { type: "application/x-pem-file" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${certificate.subject}.pem`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error("Failed to download certificate:", err);
      toast({
        title: "Error",
        description: "Failed to download certificate",
        variant: "destructive",
      });
    }
  };

  const handleDownloadDER = async () => {
    if (!certificate) return;

    try {
      const derData = certificate.derEncoded;
      if (!derData) {
        // Fallback: convert PEM to DER
        const pemData = certificate.pemEncoded;
        if (!pemData) {
          toast({
            title: "Error",
            description: "Certificate data not available",
            variant: "destructive",
          });
          return;
        }

        const base64Data = pemData
          .replace(/-----BEGIN CERTIFICATE-----/, "")
          .replace(/-----END CERTIFICATE-----/, "")
          .replace(/\s/g, "");
        const binaryString = atob(base64Data);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        const blob = new Blob([bytes], { type: "application/x-x509-ca-cert" });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${certificate.subject}.der`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        return;
      }

      // Use DER data directly if available
      const bytes = Uint8Array.from(atob(derData), c => c.charCodeAt(0));
      const blob = new Blob([bytes], { type: "application/x-x509-ca-cert" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${certificate.subject}.der`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      console.error("Failed to download certificate:", err);
      toast({
        title: "Error",
        description: "Failed to download certificate",
        variant: "destructive",
      });
    }
  };

  const handleRevoke = async () => {
    if (!certificate) return;

    const reason = prompt(`Enter revocation reason (${REVOCATION_REASONS.join(", ")}):`);
    if (!reason) return;
    if (!isRevocationReason(reason)) {
      toast({ title: "Invalid revocation reason", description: `Use one of: ${REVOCATION_REASONS.join(", ")}`, variant: "destructive" });
      return;
    }

    revokeMutation.mutate(reason);
  };

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
          <p className="font-medium text-destructive">Error loading certificate</p>
          <p className="text-sm text-muted-foreground">{error.message}</p>
        </div>
        <Button variant="outline" onClick={() => router.push("/ca/certificates")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Certificates
        </Button>
      </div>
    );
  }

  if (!certificate) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-4">
        <p className="text-muted-foreground">Certificate not found</p>
        <Button variant="outline" onClick={() => router.push("/ca/certificates")}>
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Certificates
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => router.push("/ca/certificates")}
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Certificate Details</h1>
          <p className="text-muted-foreground">
            View and manage certificate information
          </p>
        </div>
      </div>

      {/* Certificate Details */}
      <CertDetail
        certificate={certificate}
        onDownloadPEM={handleDownloadPEM}
        onDownloadDER={handleDownloadDER}
        onRevoke={handleRevoke}
      />

      {/* Certificate Chain */}
      {certificate.chain.length > 0 && (
        <CertChain chain={certificate.chain} currentCertId={certificate.id} />
      )}
    </div>
  );
}
