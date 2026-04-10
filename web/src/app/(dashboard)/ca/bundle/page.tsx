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
import { FileStack, Download, Clock } from "lucide-react";

/**
 * CA Bundle Page
 *
 * View and download certificate bundles including:
 * - Root CA certificates
 * - Intermediate CA certificates
 * - Full certificate chains
 * - PEM and DER format exports
 */
export default function CABundlePage() {
  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">CA Bundle</h1>
          <p className="text-muted-foreground">
            View and download certificate authority bundles and trust chains
          </p>
        </div>
      </div>

      {/* Coming Soon Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10">
              <FileStack className="h-6 w-6 text-primary" />
            </div>
            <div>
              <CardTitle>Certificate Bundle Management</CardTitle>
              <CardDescription>
                This feature is under development
              </CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4">
            <div className="rounded-lg border border-dashed p-8 text-center">
              <Clock className="mx-auto h-12 w-12 text-muted-foreground/50" />
              <h3 className="mt-4 text-lg font-semibold">Coming Soon</h3>
              <p className="mt-2 text-sm text-muted-foreground max-w-md mx-auto">
                The CA Bundle viewer will allow you to view, download, and manage
                certificate chains including root and intermediate CA certificates
                in various formats (PEM, DER, PKCS#7).
              </p>
            </div>

            {/* Planned Features */}
            <div className="grid gap-4 md:grid-cols-3">
              <div className="rounded-lg border p-4">
                <h4 className="font-medium">Root CA Bundle</h4>
                <p className="mt-1 text-sm text-muted-foreground">
                  Download the root certificate authority bundle
                </p>
                <Button variant="outline" size="sm" className="mt-3" disabled>
                  <Download className="mr-2 h-4 w-4" />
                  Download
                </Button>
              </div>
              <div className="rounded-lg border p-4">
                <h4 className="font-medium">Intermediate Bundle</h4>
                <p className="mt-1 text-sm text-muted-foreground">
                  Download intermediate CA certificates
                </p>
                <Button variant="outline" size="sm" className="mt-3" disabled>
                  <Download className="mr-2 h-4 w-4" />
                  Download
                </Button>
              </div>
              <div className="rounded-lg border p-4">
                <h4 className="font-medium">Full Chain</h4>
                <p className="mt-1 text-sm text-muted-foreground">
                  Download the complete certificate chain
                </p>
                <Button variant="outline" size="sm" className="mt-3" disabled>
                  <Download className="mr-2 h-4 w-4" />
                  Download
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
