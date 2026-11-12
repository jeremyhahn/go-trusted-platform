"use client";

import * as React from "react";
import { AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useCA, useMutation } from "@/hooks";
import { pemToBase64 } from "@/utils/pem-base64";

/**
 * Verify Certificate: POST /v1/ca/certificates/verify. The certificate
 * travels as the base64 of its PEM (a proto bytes field); it need not be
 * one this CA issued.
 */
export default function VerifyCertificatePage() {
  const ca = useCA();
  const [certificatePem, setCertificatePem] = React.useState("");

  // The PEM whose verification succeeded; a verdict is shown only for it.
  const [verifiedPem, setVerifiedPem] = React.useState<string | null>(null);

  const verifyMutation = useMutation(
    (pem: string) => ca.verifyCertificate({ certificatePem: pemToBase64(pem), verifyRevocation: true }),
    { onSuccess: (_data, pem) => setVerifiedPem(pem) }
  );

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    verifyMutation.reset();
    setVerifiedPem(null);
    verifyMutation.mutate(certificatePem.trim());
  };

  const result =
    !verifyMutation.error && !verifyMutation.isLoading && verifiedPem === certificatePem.trim()
      ? verifyMutation.data
      : undefined;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Verify Certificate</h1>
        <p className="text-muted-foreground">Check a certificate against this CA</p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Certificate</CardTitle>
          <CardDescription>Paste an X.509 certificate in PEM form</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="certificate-pem">Certificate (PEM)</Label>
              <Textarea
                id="certificate-pem"
                rows={10}
                className="font-mono text-xs"
                value={certificatePem}
                onChange={(e) => {
                  setCertificatePem(e.target.value);
                  verifyMutation.reset();
                  setVerifiedPem(null);
                }}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </div>
            <div>
              <Button type="submit" disabled={!certificatePem.trim() || verifyMutation.isLoading}>
                Verify
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {verifyMutation.error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <p className="text-sm text-destructive">{verifyMutation.error.message}</p>
        </div>
      )}

      {result && (
        <Card>
          <CardHeader>
            <CardTitle data-testid="verify-result">
              {result.valid ? "Certificate is valid" : "Certificate is not valid"}
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            <p data-testid="verify-revocation" className="text-muted-foreground">
              Revocation status checked
            </p>
            {(result.chain ?? []).length > 0 && (
              <div data-testid="verify-chain">
                <span className="text-muted-foreground">Chain: </span>
                {(result.chain ?? []).join(" → ")}
              </div>
            )}
            {(result.errors ?? []).length > 0 && (
              <ul className="list-disc pl-5 text-destructive">
                {(result.errors ?? []).map((err) => (
                  <li key={err}>{err}</li>
                ))}
              </ul>
            )}
            {(result.warnings ?? []).length > 0 && (
              <ul className="list-disc pl-5 text-muted-foreground">
                {(result.warnings ?? []).map((w) => (
                  <li key={w}>{w}</li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
