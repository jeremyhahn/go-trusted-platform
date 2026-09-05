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
import { FileStack, Download, Copy, Loader2 } from "lucide-react";
import { useCA, useApi, useToast } from "@/hooks";

/**
 * CA Bundle Page
 *
 * Pulls the platform's CA bundle from GET /api/v1/ca/bundle via the SDK
 * and renders the PEM-encoded chain. Supports copy-to-clipboard and a
 * direct PEM download. The page replaces the previous "Coming Soon"
 * placeholder so the xkey + dashboard CA bundle workflows have a
 * working surface.
 */
export default function CABundlePage() {
  const ca = useCA();
  const { toast } = useToast();
  const {
    data: bundleResponse,
    isLoading,
    error,
    refetch,
  } = useApi(() => ca.getBundle(), []);

  // The platform REST envelope wraps every payload as
  //   {code, error, success, payload: {...}}
  // and the CA endpoint's payload itself wraps the PEM another level deep:
  //   {payload: {bundle: {pem: "<base64-PEM>", certificates, certCount}}}
  // useApi may or may not unwrap the outer envelope depending on SDK shape,
  // and SDK refactors have also produced bundle as a flat string. Tolerate
  // every observed shape and always return decoded PEM with newlines so the
  // <pre> renders one cert per block instead of one giant line that
  // overflows the page horizontally.
  const pem: string = React.useMemo(() => {
    const decode = (s: string): string => {
      if (!s) return "";
      if (s.startsWith("-----")) return s;
      try { return atob(s); } catch { return s; }
    };
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const tryNode = (n: any): string => {
      if (!n) return "";
      if (typeof n === "string") return decode(n);
      if (typeof n.pem === "string") return decode(n.pem);
      if (typeof n.pemData === "string") return decode(n.pemData);
      if (typeof n.bundle === "string") return decode(n.bundle);
      if (n.bundle) return tryNode(n.bundle);
      return "";
    };
    // Reads the REST wire shape, which differs from the SDK/proto declaration — #445; typed once that contract is decided.
    const r = bundleResponse as any;
    if (!r) return "";
    return tryNode(r.payload) || tryNode(r);
  }, [bundleResponse]);

  const certCount = React.useMemo(() => {
    if (!pem) return 0;
    return (pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length;
  }, [pem]);

  const handleCopy = async () => {
    if (!pem) return;
    try {
      await navigator.clipboard.writeText(pem);
      toast({ title: "Copied", description: "CA bundle copied to clipboard." });
    } catch {
      toast({
        title: "Copy failed",
        description: "Could not access the clipboard.",
        variant: "destructive",
      });
    }
  };

  const handleDownload = () => {
    if (!pem) return;
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ca-bundle.pem";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">CA Bundle</h1>
          <p className="text-muted-foreground">
            View and download the certificate authority trust chain
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" onClick={() => refetch()} disabled={isLoading}>
            {isLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
            Refresh
          </Button>
          <Button variant="outline" onClick={handleCopy} disabled={!pem}>
            <Copy className="mr-2 h-4 w-4" />
            Copy PEM
          </Button>
          <Button onClick={handleDownload} disabled={!pem}>
            <Download className="mr-2 h-4 w-4" />
            Download
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <FileStack className="h-6 w-6 text-primary" />
            </div>
            <div>
              <CardTitle>Trust Chain</CardTitle>
              <CardDescription>
                {certCount > 0
                  ? `${certCount} certificate${certCount === 1 ? "" : "s"} in chain`
                  : "Platform CA bundle"}
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {error ? (
            <div className="rounded-md border border-destructive/50 bg-destructive/10 p-4 text-sm text-destructive">
              Failed to load CA bundle: {String(error.message ?? error)}
            </div>
          ) : isLoading ? (
            <div className="flex items-center justify-center py-12 text-muted-foreground">
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Loading CA bundle...
            </div>
          ) : pem ? (
            // whitespace-pre-wrap + break-all so a single long base64 line
            // (when the upstream decode fails) still wraps and never breaks
            // the page layout. font-mono keeps the PEM legible.
            <pre className="max-h-[480px] overflow-auto whitespace-pre-wrap break-all rounded-md border bg-muted p-4 font-mono text-xs leading-relaxed">
              {pem}
            </pre>
          ) : (
            <div className="rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground">
              No CA bundle available.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
