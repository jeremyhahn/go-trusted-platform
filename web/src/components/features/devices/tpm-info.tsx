'use client';

/**
 * TPMInfo Component
 * Display TPM information and details
 */

import { Shield, Check, X } from 'lucide-react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import type { TPMInfo } from '@/types/device';

interface TPMInfoProps {
  tpm?: TPMInfo;
}

export function TPMInfo({ tpm }: TPMInfoProps) {
  if (!tpm) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            TPM Information
          </CardTitle>
          <CardDescription>
            No TPM detected on this device
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <X className="h-4 w-4 text-red-500" />
            <span>This device does not have a Trusted Platform Module</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-green-600" />
          TPM Information
        </CardTitle>
        <CardDescription>
          Trusted Platform Module details
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <dl className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div>
            <dt className="text-sm font-medium text-muted-foreground">Manufacturer</dt>
            <dd className="mt-1 text-sm font-medium">{tpm.manufacturer}</dd>
          </div>

          <div>
            <dt className="text-sm font-medium text-muted-foreground">TPM Version</dt>
            <dd className="mt-1">
              <Badge variant="outline">{tpm.version}</Badge>
            </dd>
          </div>

          <div>
            <dt className="text-sm font-medium text-muted-foreground">Firmware Version</dt>
            <dd className="mt-1 text-sm">{tpm.firmwareVersion}</dd>
          </div>

          <div>
            <dt className="text-sm font-medium text-muted-foreground">Status</dt>
            <dd className="mt-1">
              <Badge variant="default" className="bg-green-600">
                Active
              </Badge>
            </dd>
          </div>
        </dl>

        <div className="space-y-2 rounded-lg border border-border bg-muted/50 p-4">
          <h4 className="text-sm font-medium">Key Configuration</h4>
          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Endorsement Key (EK)</span>
              {tpm.hasEK ? (
                <span className="flex items-center gap-1 text-green-600">
                  <Check className="h-4 w-4" />
                  Present
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-600">
                  <X className="h-4 w-4" />
                  Not found
                </span>
              )}
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Storage Root Key (SRK)</span>
              {tpm.hasSRK ? (
                <span className="flex items-center gap-1 text-green-600">
                  <Check className="h-4 w-4" />
                  Present
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-600">
                  <X className="h-4 w-4" />
                  Not found
                </span>
              )}
            </div>
          </div>
        </div>

        {tpm.version.startsWith('2') && (
          <div className="rounded-lg border border-border bg-blue-50 dark:bg-blue-950/20 p-4">
            <div className="flex items-start gap-3">
              <Shield className="h-5 w-5 text-blue-600 mt-0.5" />
              <div className="space-y-1">
                <p className="text-sm font-medium text-blue-900 dark:text-blue-100">
                  TPM 2.0 Detected
                </p>
                <p className="text-sm text-blue-700 dark:text-blue-300">
                  This device supports modern TPM 2.0 features including enhanced attestation,
                  policy-based authorization, and cryptographic agility.
                </p>
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
