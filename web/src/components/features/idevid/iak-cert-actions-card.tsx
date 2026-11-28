'use client';

/**
 * IAKCertActionsCard — the Activate credential card: runs ActivateCredential
 * (`POST /api/v1/idevid/activate-credential`) through the SDK client (#2055).
 * Delete IAK certificate is the TPM status page's control, not this card's.
 *
 * A refusal from the control plane is shown verbatim. The decrypted secret is
 * shown once and kept only in component state: never stored, never logged.
 */

import { useState } from 'react';
import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useIDevIDCerts } from '@/hooks/use-idevid-certs';

export function IAKCertActionsCard() {
  const certs = useIDevIDCerts();
  const { toast } = useToast();
  const [blob, setBlob] = useState('');
  const [secret, setSecret] = useState('');
  const [decrypted, setDecrypted] = useState('');
  const [busy, setBusy] = useState(false);

  const activate = async () => {
    setBusy(true);
    try {
      const res = await certs.activateCredential(blob, secret);
      if (res.success && res.data) {
        setDecrypted(res.data.decryptedSecret ?? '');
        setBlob('');
        setSecret('');
        toast({ title: 'Credential activated', description: res.data.status.message, variant: 'success' });
      } else {
        setDecrypted('');
        toast({
          title: 'Activate credential failed',
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="iak-cert-actions-card">
      <CardHeader>
        <CardTitle>Activate credential</CardTitle>
        <CardDescription>Activate a credential made for the IAK.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <Label htmlFor="activate-blob">Credential blob (base64)</Label>
          <Input
            id="activate-blob"
            aria-label="Credential blob (base64)"
            value={blob}
            onChange={(e) => setBlob(e.target.value)}
          />
          <Label htmlFor="activate-secret-input">Secret (base64)</Label>
          <Input
            id="activate-secret-input"
            aria-label="Secret (base64)"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
          />
          <Gated op="POST /api/v1/idevid/activate-credential">
            <Button onClick={activate} disabled={busy || blob.trim() === '' || secret.trim() === ''}>
              Activate credential
            </Button>
          </Gated>
          {decrypted !== '' && (
            <div className="flex items-center gap-2">
              <code data-testid="activate-secret" className="rounded bg-muted p-2 text-xs font-mono break-all">
                {decrypted}
              </code>
              <Button variant="outline" size="sm" onClick={() => setDecrypted('')}>
                Hide
              </Button>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
