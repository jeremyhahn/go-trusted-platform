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
import { ShieldX, Download, RefreshCw, Clock } from "lucide-react";

/**
 * Certificate Revocation List (CRL) Page
 *
 * View and manage certificate revocation lists:
 * - View current CRL
 * - Download CRL in various formats
 * - View revoked certificates
 * - Generate new CRL
 * - Configure CRL distribution points
 */
export default function CRLPage() {
  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">
            Certificate Revocation List
          </h1>
          <p className="text-muted-foreground">
            View and manage certificate revocation lists (CRL) for the CA
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" disabled>
            <RefreshCw className="mr-2 h-4 w-4" />
            Generate CRL
          </Button>
          <Button disabled>
            <Download className="mr-2 h-4 w-4" />
            Download CRL
          </Button>
        </div>
      </div>

      {/* Coming Soon Card */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-destructive/10">
              <ShieldX className="h-6 w-6 text-destructive" />
            </div>
            <div>
              <CardTitle>CRL Management</CardTitle>
              <CardDescription>This feature is under development</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col gap-4">
            <div className="rounded-lg border border-dashed p-8 text-center">
              <Clock className="mx-auto h-12 w-12 text-muted-foreground/50" />
              <h3 className="mt-4 text-lg font-semibold">Coming Soon</h3>
              <p className="mt-2 text-sm text-muted-foreground max-w-md mx-auto">
                The CRL management page will allow you to view revoked certificates,
                generate new CRLs, configure distribution points, and download CRLs
                in PEM and DER formats.
              </p>
            </div>

            {/* Planned Features */}
            <div className="grid gap-4 md:grid-cols-2">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Current CRL Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Last Updated:</span>
                      <span>--</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Next Update:</span>
                      <span>--</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">
                        Revoked Certificates:
                      </span>
                      <span>--</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">CRL Number:</span>
                      <span>--</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Distribution Points</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm text-muted-foreground">
                    <p>Configure CRL distribution points for certificate validation.</p>
                    <ul className="list-disc list-inside space-y-1">
                      <li>HTTP distribution point</li>
                      <li>LDAP distribution point</li>
                      <li>Delta CRL support</li>
                    </ul>
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
