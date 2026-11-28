'use client';

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import type { AttestVMResponse } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Gated } from '@/components/features/capabilities/gated';
import { useCompute, useToast } from '@/hooks';

const ATTEST_OP = 'POST /api/v1/compute/vms/{id}/attest';
const NONCE_BYTES = 32;

function errorText(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  return 'the control plane refused the attestation';
}

// freshNonce returns NONCE_BYTES random bytes, base64-encoded, for one quote.
function freshNonce(): string {
  const bytes = new Uint8Array(NONCE_BYTES);
  crypto.getRandomValues(bytes);
  let binary = '';
  bytes.forEach((b) => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function truncate(value: string, keep = 32): string {
  return value.length > keep ? `${value.slice(0, keep)}…` : value;
}

/**
 * VMAttestCard asks the control plane for a TPM quote of the VM (AttestVM)
 * over a fresh nonce, behind the server's capability gate (#2044), and shows
 * the quote's signature scheme, AK and PCR values.
 */
export function VMAttestCard({ vmId }: { vmId: string }) {
  const compute = useCompute();
  const { toast } = useToast();
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<AttestVMResponse | null>(null);

  const fail = (message: string) => {
    toast({ title: 'Attestation failed', description: message, variant: 'destructive' });
  };

  const handleAttest = async () => {
    setPending(true);
    try {
      const res = await compute.attestVM({ vmId, nonce: freshNonce() });
      if (res.success === false || !res.data) {
        fail(errorText(res.error ?? 'the control plane returned no quote'));
        return;
      }
      setResult(res.data);
    } catch (err) {
      fail(errorText(err));
    } finally {
      setPending(false);
    }
  };

  const status = result?.status;
  const statusText = status ? status.message || (status.success ? 'success' : 'failed') : '';

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" />
          Attestation
        </CardTitle>
        <Gated op={ATTEST_OP}>
          <Button variant="outline" size="sm" onClick={() => void handleAttest()} disabled={pending}>
            Attest VM
          </Button>
        </Gated>
      </CardHeader>
      <CardContent>
        {!result ? (
          <p className="text-sm text-muted-foreground">
            Request a TPM quote of this VM over a fresh nonce.
          </p>
        ) : (
          <div className="space-y-4" data-testid="vm-attest-result">
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Status</span>
              <span className="font-medium">{statusText || '-'}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Signature algorithm</span>
              <span className="font-mono">{result.signatureAlgorithm || '-'}</span>
            </div>
            <div className="flex items-center justify-between gap-4 text-sm">
              <span className="text-muted-foreground">AK public key</span>
              <span className="font-mono break-all" title={result.akPublic}>
                {result.akPublic ? truncate(result.akPublic) : '-'}
              </span>
            </div>
            {result.pcrValues && result.pcrValues.length > 0 ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>PCR</TableHead>
                    <TableHead>Bank</TableHead>
                    <TableHead>Value</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {result.pcrValues.map((pcr) => (
                    <TableRow key={`${pcr.bank}-${pcr.index}`}>
                      <TableCell>{pcr.index}</TableCell>
                      <TableCell>{pcr.bank}</TableCell>
                      <TableCell className="font-mono break-all">{pcr.value}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No PCR values in the quote</p>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
