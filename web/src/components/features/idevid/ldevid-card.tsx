'use client';

/**
 * LDevIDCard — creates a locally significant device identity (LDevID) with
 * CreateLDevID through the useLDevID hook (POST /api/v1/idevid/ldevid) and
 * shows the CSR and certificate PEM the device returns.
 *
 * Refusals (no TPM, no LDevID CA, no proven IDevID, a bad request) are shown
 * verbatim.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { LDEVID_DEFAULT_HANDLE, decodePem, useLDevID, type LDevIDAlgorithm } from '@/hooks/use-ldevid';

const ALGORITHMS: { value: LDevIDAlgorithm; label: string }[] = [
  { value: 'ECDSA_P256', label: 'ECDSA P-256' },
  { value: 'ECDSA_P384', label: 'ECDSA P-384' },
  { value: 'RSA_2048', label: 'RSA 2048' },
  { value: 'RSA_3072', label: 'RSA 3072' },
];

const HANDLE_HEX = `0x${LDEVID_DEFAULT_HANDLE.toString(16)}`;

export function LDevIDCard() {
  const { createLDevID } = useLDevID();
  const { toast } = useToast();
  const [commonName, setCommonName] = useState('');
  const [organization, setOrganization] = useState('');
  const [algorithm, setAlgorithm] = useState<LDevIDAlgorithm>('ECDSA_P256');
  const [validity, setValidity] = useState('');
  const [busy, setBusy] = useState(false);
  const [csr, setCsr] = useState('');
  const [cert, setCert] = useState('');

  const send = async () => {
    setBusy(true);
    try {
      const res = await createLDevID({
        commonName,
        organization: organization.trim() || undefined,
        algorithm,
        validityDays: validity === '' ? undefined : Number(validity),
      });
      if (res.success && res.data) {
        setCsr(decodePem(res.data.csrPem));
        setCert(decodePem(res.data.certificatePem));
        toast({ title: 'LDevID created', description: res.data.status.message, variant: 'success' });
      } else {
        const message = res.error?.message ?? 'request failed';
        setCsr('');
        setCert('');
        toast({ title: 'Create LDevID failed', description: message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="ldevid-card">
      <CardHeader>
        <CardTitle>LDevID</CardTitle>
        <CardDescription>
          Create an LDevID key and certificate on the device. The device must hold a proven IDevID.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <Label htmlFor="ldevid-cn">Common name</Label>
            <Input
              id="ldevid-cn"
              aria-label="Common name"
              value={commonName}
              onChange={(e) => setCommonName(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="ldevid-org">Organization</Label>
            <Input
              id="ldevid-org"
              aria-label="Organization"
              value={organization}
              onChange={(e) => setOrganization(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="ldevid-alg">Algorithm</Label>
            <select
              id="ldevid-alg"
              aria-label="Algorithm"
              className="h-10 w-full rounded-md border border-input bg-background px-3 text-sm"
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value as LDevIDAlgorithm)}
            >
              {ALGORITHMS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="ldevid-validity">Validity (days)</Label>
            <Input
              id="ldevid-validity"
              aria-label="Validity (days)"
              type="number"
              min={1}
              value={validity}
              onChange={(e) => setValidity(e.target.value)}
            />
          </div>
        </div>
        <p className="text-sm text-muted-foreground">Handle {HANDLE_HEX}</p>
        <Button onClick={send} disabled={busy || commonName.trim() === ''}>
          Create LDevID
        </Button>
        {csr !== '' && (
          <pre data-testid="ldevid-csr-pem" className="rounded bg-muted p-2 text-xs font-mono whitespace-pre-wrap break-all">
            {csr}
          </pre>
        )}
        {cert !== '' && (
          <pre data-testid="ldevid-cert-pem" className="rounded bg-muted p-2 text-xs font-mono whitespace-pre-wrap break-all">
            {cert}
          </pre>
        )}
      </CardContent>
    </Card>
  );
}
