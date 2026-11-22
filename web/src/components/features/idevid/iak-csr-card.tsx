'use client';

/**
 * IAKCSRCard — creates the IAK certificate signing request (CreateIAKCSR,
 * `POST /api/v1/idevid/iak/csr`) and installs a CA-issued IDevID certificate
 * (InstallIDevIDCertificate, `POST /api/v1/idevid/certificate`) or IAK
 * certificate (InstallIAKCertificate, `POST /api/v1/idevid/iak/certificate`)
 * through the SDK client (#2055).
 *
 * A refusal from the control plane is shown verbatim.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { base64ToPem, looksLikePem, useIDevIDCerts } from '@/hooks/use-idevid-certs';

export function IAKCSRCard() {
  const certs = useIDevIDCerts();
  const { toast } = useToast();
  const [commonName, setCommonName] = useState('');
  const [csr, setCsr] = useState('');
  const [pem, setPem] = useState('');
  const [busy, setBusy] = useState(false);

  const isPem = looksLikePem(pem, 'CERTIFICATE');

  const createCSR = async () => {
    setBusy(true);
    try {
      const res = await certs.createIAKCSR(commonName);
      if (res.success && res.data) {
        setCsr(base64ToPem(res.data.csrPem));
        toast({ title: 'IAK CSR created', description: res.data.status.message, variant: 'success' });
      } else {
        setCsr('');
        toast({
          title: 'Create IAK CSR failed',
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const install = async (kind: 'IDevID' | 'IAK') => {
    setBusy(true);
    try {
      const res =
        kind === 'IDevID' ? await certs.installIDevIDCertificate(pem) : await certs.installIAKCertificate(pem);
      if (res.success && res.data) {
        setPem('');
        toast({ title: `${kind} certificate installed`, description: res.data.status.message, variant: 'success' });
      } else {
        toast({
          title: `Install ${kind} certificate failed`,
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="iak-csr-card">
      <CardHeader>
        <CardTitle>IAK CSR and certificates</CardTitle>
        <CardDescription>
          Create the IAK certificate signing request, then install the certificates the CA issued.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="iak-csr-common-name">Common name</Label>
          <div className="flex gap-2">
            <Input
              id="iak-csr-common-name"
              aria-label="Common name"
              placeholder="optional"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
            />
            <Button onClick={createCSR} disabled={busy}>
              Create IAK CSR
            </Button>
          </div>
          {csr !== '' && (
            <pre
              data-testid="iak-csr-pem"
              className="rounded bg-muted p-2 text-xs font-mono break-all whitespace-pre-wrap"
            >
              {csr}
            </pre>
          )}
        </div>

        <div className="space-y-2">
          <Label htmlFor="iak-cert-pem">Certificate PEM</Label>
          <Textarea
            id="iak-cert-pem"
            aria-label="Certificate PEM"
            className="font-mono text-xs"
            value={pem}
            onChange={(e) => setPem(e.target.value)}
          />
          {pem !== '' && !isPem && (
            <p data-testid="pem-hint" className="text-sm text-muted-foreground">
              Paste one PEM CERTIFICATE block.
            </p>
          )}
          <div className="flex gap-2">
            <Button onClick={() => install('IDevID')} disabled={busy || !isPem}>
              Install IDevID certificate
            </Button>
            <Button onClick={() => install('IAK')} disabled={busy || !isPem}>
              Install IAK certificate
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
