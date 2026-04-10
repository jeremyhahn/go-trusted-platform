"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import type { CertificateDetail } from "@/types/security";
import { Download, ShieldAlert } from "lucide-react";

interface CertDetailProps {
  certificate: CertificateDetail;
  onDownloadPEM?: () => void;
  onDownloadDER?: () => void;
  onRevoke?: () => void;
}

/**
 * Certificate detail display component
 *
 * Shows comprehensive certificate information including:
 * - Subject and issuer details
 * - Validity period
 * - Public key information
 * - Extensions
 * - Download options
 */
export function CertDetail({
  certificate,
  onDownloadPEM,
  onDownloadDER,
  onRevoke,
}: CertDetailProps) {
  const isExpired = new Date(certificate.notAfter) < new Date();
  const isRevoked = certificate.status === "revoked";

  return (
    <div className="space-y-6">
      {/* Header with status and actions */}
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <h2 className="text-2xl font-semibold tracking-tight">
            {certificate.subject}
          </h2>
          <div className="flex items-center gap-2">
            <Badge
              variant={
                certificate.status === "active"
                  ? "default"
                  : certificate.status === "revoked"
                  ? "destructive"
                  : "secondary"
              }
            >
              {certificate.status}
            </Badge>
            <Badge variant="outline" className="capitalize">
              {certificate.type}
            </Badge>
          </div>
        </div>
        <div className="flex gap-2">
          {onDownloadPEM && (
            <Button variant="outline" size="sm" onClick={onDownloadPEM}>
              <Download className="h-4 w-4 mr-2" />
              PEM
            </Button>
          )}
          {onDownloadDER && (
            <Button variant="outline" size="sm" onClick={onDownloadDER}>
              <Download className="h-4 w-4 mr-2" />
              DER
            </Button>
          )}
          {onRevoke && !isRevoked && !isExpired && (
            <Button variant="destructive" size="sm" onClick={onRevoke}>
              <ShieldAlert className="h-4 w-4 mr-2" />
              Revoke
            </Button>
          )}
        </div>
      </div>

      {/* Basic Information */}
      <Card>
        <CardHeader>
          <CardTitle>Certificate Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Subject</div>
              <div className="mt-1 text-sm font-mono break-all">{certificate.subject}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Issuer</div>
              <div className="mt-1 text-sm font-mono break-all">{certificate.issuer}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Serial Number</div>
              <code className="mt-1 text-xs bg-muted px-2 py-1 rounded block">
                {certificate.serialNumber}
              </code>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Type</div>
              <div className="mt-1 text-sm capitalize">{certificate.type}</div>
            </div>
          </div>

          <Separator />

          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Valid From</div>
              <div className="mt-1 text-sm">
                {new Date(certificate.notBefore).toLocaleString()}
              </div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Valid Until</div>
              <div className={`mt-1 text-sm ${isExpired ? "text-destructive" : ""}`}>
                {new Date(certificate.notAfter).toLocaleString()}
                {isExpired && " (Expired)"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Public Key Information */}
      <Card>
        <CardHeader>
          <CardTitle>Public Key Information</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-sm font-medium text-muted-foreground">Algorithm</div>
              <div className="mt-1 text-sm">{certificate.publicKeyAlgorithm}</div>
            </div>
            <div>
              <div className="text-sm font-medium text-muted-foreground">Signature Algorithm</div>
              <div className="mt-1 text-sm">{certificate.signatureAlgorithm}</div>
            </div>
          </div>
          <div>
            <div className="text-sm font-medium text-muted-foreground mb-2">Public Key</div>
            <pre className="text-xs bg-muted p-4 rounded overflow-x-auto">
              {certificate.publicKey}
            </pre>
          </div>
        </CardContent>
      </Card>

      {/* Extensions */}
      {certificate.extensions.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Extensions</CardTitle>
            <CardDescription>
              X.509 certificate extensions and their values
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {certificate.extensions.map((ext, idx) => (
                <div key={idx} className="border-l-2 border-border pl-4">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium">{ext.name}</span>
                    {ext.critical && (
                      <Badge variant="destructive" className="text-xs">
                        Critical
                      </Badge>
                    )}
                  </div>
                  <code className="text-xs text-muted-foreground">{ext.oid}</code>
                  <div className="mt-2 text-sm">{ext.value}</div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* PEM Encoded Certificate */}
      <Card>
        <CardHeader>
          <CardTitle>PEM Encoded Certificate</CardTitle>
        </CardHeader>
        <CardContent>
          <pre className="text-xs bg-muted p-4 rounded overflow-x-auto">
            {certificate.pemEncoded}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
