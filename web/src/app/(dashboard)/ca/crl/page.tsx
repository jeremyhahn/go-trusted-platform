"use client";

import * as React from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Download, RefreshCw, ShieldX, Loader2 } from "lucide-react";
import { useApi, useCA, useToast } from "@/hooks";
import { errorMessage } from "@/utils/errors";

/**
 * Certificate Revocation List (CRL) Page
 *
 * Calls /api/v1/ca/crl through the SDK to surface the current CRL plus
 * its list of revoked certificates. The backend handler already exists
 * (pkg/webservice/v1/rest/ca/handlers.go:GetCRL) and the SDK has both
 * getCRL() (parsed JSON) and downloadCRL() (raw DER). The previous
 * "Coming Soon" stub left this surface unusable even though the API
 * was live.
 */
export default function CRLPage() {
  const ca = useCA();
  const { toast } = useToast();

  const {
    data: crlResponse,
    isLoading,
    error,
    refetch,
  } = useApi(() => ca.getCRL(), []);

  // Tolerate both shapes:
  //   - useApi unwrapping payload: { crl: {...}, timestamp }
  //   - or surfacing the full envelope: { payload: { crl: ... } }
  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const crl: any = React.useMemo(() => {
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const r = crlResponse as any;
    if (!r) return null;
    if (r.crl) return r.crl;
    if (r.payload?.crl) return r.payload.crl;
    return null;
  }, [crlResponse]);

  // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
  const revokedCerts: any[] = crl?.revokedCerts ?? crl?.revoked_certs ?? [];

  const handleDownload = async (format: "pem" | "der") => {
    if (!crl?.data) {
      toast({
        title: "No CRL available",
        description: "The CA has not produced a CRL yet.",
        variant: "destructive",
      });
      return;
    }
    try {
      // crl.data is base64-encoded DER from the REST envelope. PEM
      // wraps it with the standard X509 CRL header / footer. We do
      // both transformations client-side so a misconfigured object
      // store on the backend doesn't block download.
      const derBytes = Uint8Array.from(atob(crl.data), (c) => c.charCodeAt(0));
      let blob: Blob;
      let filename: string;
      if (format === "der") {
        blob = new Blob([derBytes], { type: "application/pkix-crl" });
        filename = "platform.crl";
      } else {
        const b64 = crl.data
          .replace(/.{64}/g, (m: string) => m + "\n")
          .replace(/\n?$/, "\n");
        const pem = `-----BEGIN X509 CRL-----\n${b64}-----END X509 CRL-----\n`;
        blob = new Blob([pem], { type: "application/x-pem-file" });
        filename = "platform-crl.pem";
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      toast({ title: "CRL downloaded", description: filename });
    } catch (e) {
      toast({
        title: "Download failed",
        description: errorMessage(e, "Unknown error"),
        variant: "destructive",
      });
    }
  };

  const formatTs = (v: string | undefined | null): string => {
    if (!v) return "—";
    const d = new Date(v);
    if (!Number.isFinite(d.getTime())) return "—";
    return d.toLocaleString();
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Certificate Revocation List
          </h1>
          <p className="text-muted-foreground">
            View revoked certificates and download the current CRL.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            {isLoading ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <RefreshCw className="mr-2 h-4 w-4" />
            )}
            Refresh
          </Button>
          <Button variant="outline" onClick={() => handleDownload("pem")} disabled={!crl?.data}>
            <Download className="mr-2 h-4 w-4" />
            Download PEM
          </Button>
          <Button onClick={() => handleDownload("der")} disabled={!crl?.data}>
            <Download className="mr-2 h-4 w-4" />
            Download DER
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <ShieldX className="h-6 w-6 text-primary" />
            </div>
            <div>
              <CardTitle>Current CRL</CardTitle>
              <CardDescription>
                Signed by the issuing CA; consumers verify with the CA bundle.
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {error ? (
            <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
              Failed to load CRL: {error.message}
            </div>
          ) : isLoading && !crl ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Loading CRL...
            </div>
          ) : (
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Validity</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last update</span>
                      <span>{formatTs(crl?.lastUpdate ?? crl?.last_update)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Next update</span>
                      <span>{formatTs(crl?.nextUpdate ?? crl?.next_update)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Revoked count</span>
                      <Badge variant={revokedCerts.length > 0 ? "destructive" : "secondary"}>
                        {crl?.revokedCount ?? crl?.revoked_count ?? revokedCerts.length}
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Distribution</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <p>
                      Consumers fetch the CRL via{" "}
                      <code className="font-mono text-xs">GET /api/v1/ca/crl</code>.
                      The PEM / DER download buttons above produce identical
                      bytes to the over-the-wire response.
                    </p>
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Revoked Certificates</CardTitle>
          <CardDescription>
            {revokedCerts.length === 0
              ? "No certificates have been revoked."
              : `${revokedCerts.length} certificate${
                  revokedCerts.length === 1 ? "" : "s"
                } currently revoked.`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {revokedCerts.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Serial</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Revoked at</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {revokedCerts.map((r, i) => (
                  <TableRow key={r.serial ?? i}>
                    <TableCell className="font-mono text-xs">
                      {r.serial}
                    </TableCell>
                    <TableCell>{String(r.reason ?? "—")}</TableCell>
                    <TableCell>
                      {formatTs(r.revocationTime ?? r.revocation_time)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
