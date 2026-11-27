'use client';

/**
 * BMCCertCard names the certificate operations of one BMC profile and offers
 * none of them. Factory restore verifies the regenerated certificate against
 * the old SPKI/TOFU pin, so it fails after the BMC has changed and leaves the
 * stored pin and the TLSA records stale (#2199); the profile enrolment path
 * cannot capture a trust pin yet, and a web certificate replace leaves the
 * stored pin stale. No ceremony is offered until the server carries the BMC
 * trust pin across a certificate change.
 */
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

export interface BMCCertCardProps {
  profileID: string;
}

export function BMCCertCard({ profileID }: BMCCertCardProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>BMC certificate</CardTitle>
        <CardDescription>BMC profile {profileID}</CardDescription>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground" data-testid="bmc-cert-held-back">
          Enrolment, web certificate replacement and factory certificate restore are unavailable until the server
          carries the BMC trust pin across a certificate change.
        </p>
      </CardContent>
    </Card>
  );
}
