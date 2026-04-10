"use client";

import * as React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Copy, Check } from "lucide-react";

interface CSRViewerProps {
  csr: string;
  subject?: string;
  publicKeyAlgorithm?: string;
}

/**
 * Certificate Signing Request (CSR) viewer component
 *
 * Features:
 * - PEM-encoded CSR display
 * - Copy to clipboard
 * - Subject and key algorithm display
 */
export function CSRViewer({ csr, subject, publicKeyAlgorithm }: CSRViewerProps) {
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(csr);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <Card>
      <CardHeader>
        <div className="flex items-start justify-between">
          <div>
            <CardTitle>Certificate Signing Request</CardTitle>
            <CardDescription>
              PEM-encoded CSR for certificate issuance
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            disabled={copied}
          >
            {copied ? (
              <>
                <Check className="h-4 w-4 mr-2" />
                Copied
              </>
            ) : (
              <>
                <Copy className="h-4 w-4 mr-2" />
                Copy
              </>
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* CSR Metadata */}
        {(subject || publicKeyAlgorithm) && (
          <div className="grid grid-cols-2 gap-4 p-4 bg-muted rounded-lg">
            {subject && (
              <div>
                <div className="text-sm font-medium text-muted-foreground">Subject</div>
                <div className="mt-1 text-sm font-mono break-all">{subject}</div>
              </div>
            )}
            {publicKeyAlgorithm && (
              <div>
                <div className="text-sm font-medium text-muted-foreground">
                  Public Key Algorithm
                </div>
                <div className="mt-1 text-sm">{publicKeyAlgorithm}</div>
              </div>
            )}
          </div>
        )}

        {/* CSR Content */}
        <div>
          <pre className="text-xs bg-muted p-4 rounded overflow-x-auto border">
            {csr}
          </pre>
        </div>
      </CardContent>
    </Card>
  );
}
