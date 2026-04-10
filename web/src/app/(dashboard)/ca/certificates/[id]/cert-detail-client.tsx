"use client";

import * as React from "react";
import { use } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { CertDetail } from "@/components/features/ca/cert-detail";
import { CertChain } from "@/components/features/ca/cert-chain";
import { useCA, useApi, useMutation, useToast } from "@/hooks";
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
export default function CertificateDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const ca = useCA();
  const { toast } = useToast();

  // SDK getCertificate takes serial number as a string parameter
  const { data: response, isLoading: loading, error, refetch } = useApi(
    () => ca.getCertificate(id),
    [id]
  );

  // Transform SDK Certificate to UI CertificateDetail type
  const certificate = React.useMemo(() => {
    if (!response?.certificate) return null;

    const cert = response.certificate;

    // Map SDK CertificateStatus to UI status
    const mapStatus = (status: string): 'active' | 'revoked' | 'expired' => {
      if (status === 'REVOKED') return 'revoked';
      if (status === 'EXPIRED') return 'expired';
      return 'active';
    };

    // Map certificate type (SDK doesn't have type, infer from isCA)
    const mapType = (isCA: boolean): 'root' | 'intermediate' | 'leaf' => {
      if (!isCA) return 'leaf';
      // TODO: Distinguish between root and intermediate CAs
      return 'intermediate';
    };

    return {
      id: cert.serial,
      subject: cert.subject.commonName,
      issuer: cert.issuer,
      serialNumber: cert.serial,
      type: mapType(cert.isCA),
      status: mapStatus(cert.status),
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      publicKeyAlgorithm: cert.keyAlgorithm,
      signatureAlgorithm: cert.signatureAlgorithm,
      publicKey: '', // TODO: Extract from PEM if needed
      extensions: [], // TODO: Map from keyUsage and extKeyUsage
      chain: [], // TODO: Fetch certificate chain
      pemEncoded: cert.pem || '',
      derEncoded: cert.der || '',
    } as CertificateDetail;
  }, [response]);

  const revokeMutation = useMutation(
    (reason: string) => ca.revokeCertificate({
      serial: id,
      reason: reason as any // TODO: Type should be RevocationReason enum
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

    const reason = prompt("Enter revocation reason:");
    if (!reason) return;

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
