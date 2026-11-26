'use client';

/**
 * BMCWebCertCard shows the BMC web certificate (#2039).
 *
 * It reads BMCService.GetWebCertificate (`GET /bmc/{profileID}/cert`) through
 * useBMCStatus on mount and on Refresh, words the days remaining, and warns
 * when fewer than 30 days remain or the certificate has expired. A refusal
 * from the control plane is shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { useBMCStatus, type BMCWebCertificate } from '@/hooks/use-bmc-status';

/** Days remaining under which the card warns. */
export const BMC_CERT_WARN_DAYS = 30;

export interface BMCWebCertCardProps {
  profileID: string;
}

/**
 * certExpired reports whether a certificate has expired. days_remaining is a
 * whole-day count from the server, so a certificate whose not_after passed
 * earlier today still reports 0: not_after decides, and an unparsable
 * not_after falls back to days_remaining.
 */
export function certExpired(cert: BMCWebCertificate, now = Date.now()): boolean {
  return cert.days_remaining < 0 || Date.parse(cert.not_after) <= now;
}

/** certExpiryText words the days remaining of a certificate. */
export function certExpiryText(days: number, expired = days < 0): string {
  if (days < 0) {
    const ago = -days;
    return `Expired ${ago} ${ago === 1 ? 'day' : 'days'} ago`;
  }
  if (days === 0) return expired ? 'Expired today' : 'Expires today';
  if (days === 1) return 'Expires in 1 day';
  return `Expires in ${days} days`;
}

function expiryVariant(days: number, expired: boolean): 'destructive' | 'secondary' | 'outline' {
  if (expired) return 'destructive';
  if (days < BMC_CERT_WARN_DAYS) return 'secondary';
  return 'outline';
}

export function BMCWebCertCard({ profileID }: BMCWebCertCardProps) {
  const { getWebCertificate } = useBMCStatus(profileID);
  const [cert, setCert] = useState<BMCWebCertificate | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    const res = await getWebCertificate();
    if (res.success && res.data) {
      setCert(res.data);
      setError(null);
    } else {
      setCert(null);
      setError(res.error?.message ?? 'request failed');
    }
    setLoading(false);
  }, [getWebCertificate]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const expired = cert !== null && certExpired(cert);

  return (
    <Card>
      <CardHeader>
        <CardTitle>BMC web certificate</CardTitle>
        <CardDescription>BMC profile {profileID}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {error !== null && <p role="alert">Web certificate unavailable: {error}</p>}
        {cert && (
          <>
            <dl data-testid="bmc-web-cert" className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
              <dt>Subject</dt>
              <dd>{cert.subject}</dd>
              <dt>Issuer</dt>
              <dd>{cert.issuer}</dd>
              <dt>Serial number</dt>
              <dd>{cert.serial_number}</dd>
              <dt>Not before</dt>
              <dd>{cert.not_before}</dd>
              <dt>Not after</dt>
              <dd>{cert.not_after}</dd>
              <dt>Expiry</dt>
              <dd>
                <Badge variant={expiryVariant(cert.days_remaining, expired)}>
                  <span data-testid="bmc-cert-expiry">{certExpiryText(cert.days_remaining, expired)}</span>
                </Badge>
              </dd>
            </dl>
            {(expired || cert.days_remaining < BMC_CERT_WARN_DAYS) && (
              <Alert data-testid="bmc-cert-warning" variant={expired ? 'destructive' : 'default'}>
                <AlertDescription>
                  {expired
                    ? 'The BMC web certificate has expired.'
                    : `The BMC web certificate expires in fewer than ${BMC_CERT_WARN_DAYS} days.`}
                </AlertDescription>
              </Alert>
            )}
          </>
        )}
        <Button variant="outline" size="sm" disabled={loading} onClick={() => void reload()}>
          Refresh
        </Button>
      </CardContent>
    </Card>
  );
}
