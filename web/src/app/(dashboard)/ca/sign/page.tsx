"use client";

import * as React from "react";
import { AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { useCA, useMutation } from "@/hooks";
import { base64ToPem } from "@/utils/pem-base64";

/** The issued certificate as the REST layer sends it. */
interface IssuedCertWire {
  serial?: string;
  commonName?: string;
  common_name?: string;
  pem?: string;
}

/**
 * Sign CSR: POST /v1/ca/sign-csr. The CA certifies, for code signing, the
 * KMS key the CSR names; the caller's token needs the ca:sign-csr scope.
 */
export default function SignCSRPage() {
  const ca = useCA();
  const [csrPem, setCsrPem] = React.useState("");
  const [validDays, setValidDays] = React.useState("");

  // The CSR and validity the shown certificate was issued for; a certificate
  // is shown only while the form still holds that input.
  const [signedFor, setSignedFor] = React.useState<string | null>(null);
  const inputKey = (csr: string, days: string) => `${csr}\n${days}`;

  const signMutation = useMutation(
    (req: { csrPem: string; validDays?: number; key: string }) =>
      ca.signCSR({
        csrPem: req.csrPem,
        ...(req.validDays !== undefined ? { validDays: req.validDays } : {}),
      }),
    { onSuccess: (_data, req) => setSignedFor(req.key) }
  );

  const clearResult = () => {
    signMutation.reset();
    setSignedFor(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    clearResult();
    const days = Number.parseInt(validDays, 10);
    signMutation.mutate({
      csrPem: csrPem.trim(),
      ...(Number.isFinite(days) && days > 0 ? { validDays: days } : {}),
      key: inputKey(csrPem, validDays),
    });
  };

  const issued =
    !signMutation.error && !signMutation.isLoading && signedFor === inputKey(csrPem, validDays)
      ? (signMutation.data as unknown as { certificate?: IssuedCertWire } | undefined)?.certificate
      : undefined;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Sign CSR</h1>
        <p className="text-muted-foreground">
          Certify the key a certificate signing request names, for code signing
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Certificate signing request</CardTitle>
          <CardDescription>Paste a PKCS#10 request in PEM form</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="csr-pem">CSR (PEM)</Label>
              <Textarea
                id="csr-pem"
                rows={10}
                className="font-mono text-xs"
                value={csrPem}
                onChange={(e) => {
                  setCsrPem(e.target.value);
                  clearResult();
                }}
                placeholder="-----BEGIN CERTIFICATE REQUEST-----"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="valid-days">Validity (days)</Label>
              <Input
                id="valid-days"
                type="number"
                min={1}
                value={validDays}
                onChange={(e) => {
                  setValidDays(e.target.value);
                  clearResult();
                }}
                placeholder="CA default"
              />
            </div>
            <div>
              <Button type="submit" disabled={!csrPem.trim() || signMutation.isLoading}>
                Sign CSR
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {signMutation.error && (
        <div className="flex items-center gap-2 p-4 bg-destructive/10 border border-destructive rounded-lg">
          <AlertCircle className="h-4 w-4 text-destructive" />
          <p className="text-sm text-destructive">{signMutation.error.message}</p>
        </div>
      )}

      {issued && (
        <Card>
          <CardHeader>
            <CardTitle>Certificate issued</CardTitle>
            <CardDescription>{issued.commonName ?? issued.common_name ?? ""}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2 text-sm">
            <div>
              <span className="text-muted-foreground">Serial: </span>
              <span data-testid="signed-serial">{issued.serial ?? ""}</span>
            </div>
            <pre data-testid="signed-pem" className="overflow-x-auto rounded bg-muted p-2 font-mono text-xs">
              {issued.pem ? base64ToPem(issued.pem) : ""}
            </pre>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
