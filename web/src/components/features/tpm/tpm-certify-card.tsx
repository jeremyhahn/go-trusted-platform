'use client';

/**
 * TPMCertifyCard: asks the TPM to certify, under its IAK, that a key at a
 * persistent handle is resident (TPMService.Certify, POST /v1/tpm/certify,
 * #2068) and shows the signed result. A refusal is shown verbatim.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useTPMCertify, type TPMCertifyResult } from '@/hooks/use-tpm-certify';
import { base64ToHex, textToBase64 } from '@/hooks/use-tpm-ops';

const PERSISTENT_MIN = 0x81000000;
const PERSISTENT_MAX = 0x81ffffff;

/** "0x81000001" or "2164260865" -> the number when it is in 0x81000000-0x81FFFFFF; anything else (blank included) -> NaN. */
export function parsePersistentHandle(text: string): number {
  const s = text.trim();
  let n = NaN;
  if (/^0x[0-9a-f]+$/i.test(s)) {
    n = parseInt(s.slice(2), 16);
  } else if (/^[0-9]+$/.test(s)) {
    n = Number(s);
  }
  return n >= PERSISTENT_MIN && n <= PERSISTENT_MAX ? n : NaN;
}

/** Hex of base64 bytes, cut to the first 64 characters. */
function shortHex(b64?: string): string {
  const hex = b64 ? base64ToHex(b64) : '';
  return hex.length > 64 ? `${hex.slice(0, 64)}…` : hex;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function TPMCertifyCard() {
  const { certify } = useTPMCertify();
  const { toast } = useToast();
  const [handleText, setHandleText] = useState('');
  const [password, setPassword] = useState('');
  const [nonceText, setNonceText] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<TPMCertifyResult | null>(null);

  const readHandle = (): number | null => {
    const handle = parsePersistentHandle(handleText);
    if (Number.isNaN(handle)) {
      toast({
        title: 'Invalid handle',
        description: 'a persistent handle is 0x81000000-0x81FFFFFF',
        variant: 'destructive',
      });
      return null;
    }
    return handle;
  };

  const handleCertify = async () => {
    const keyHandle = readHandle();
    if (keyHandle === null) return;
    setBusy(true);
    try {
      const res = await certify({
        keyHandle,
        keyPassword: password || undefined,
        nonce: nonceText ? textToBase64(nonceText) : undefined,
      });
      if (res.success && res.data) {
        setResult(res.data);
        toast({
          title: 'Key certified',
          description: `signed under ${res.data.signatureAlgorithm ?? 'the IAK'}`,
          variant: 'success',
        });
      } else {
        setResult(null);
        toast({
          title: 'Certify failed',
          description: res.error?.message || 'the TPM did not certify the key',
          variant: 'destructive',
        });
      }
    } catch (err) {
      setResult(null);
      toast({ title: 'Certify failed', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="tpm-certify-card">
      <CardHeader>
        <CardTitle>Certify a key</CardTitle>
        <CardDescription>
          The TPM signs, under its IAK, that a key at a persistent handle is resident.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1">
            <Label htmlFor="tpm-certify-handle">Key handle</Label>
            <Input
              id="tpm-certify-handle"
              aria-label="Key handle"
              placeholder="0x81000001"
              value={handleText}
              onChange={(e) => setHandleText(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="tpm-certify-password">Key password</Label>
            <Input
              id="tpm-certify-password"
              aria-label="Key password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="tpm-certify-nonce">Nonce (text)</Label>
            <Input
              id="tpm-certify-nonce"
              aria-label="Nonce (text)"
              value={nonceText}
              onChange={(e) => setNonceText(e.target.value)}
            />
          </div>
        </div>
        <Button onClick={handleCertify} disabled={busy}>
          Certify
        </Button>

        {result && (
          <dl data-testid="tpm-certify-result" className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Signature algorithm</dt>
            <dd>{result.signatureAlgorithm ?? '-'}</dd>
            <dt className="text-muted-foreground">Nonce</dt>
            <dd className="font-mono break-all">{result.nonce ? base64ToHex(result.nonce) : '-'}</dd>
            <dt className="text-muted-foreground">Certify info</dt>
            <dd className="font-mono break-all">{shortHex(result.certifyInfo) || '-'}</dd>
            <dt className="text-muted-foreground">Signature</dt>
            <dd className="font-mono break-all">{shortHex(result.signature) || '-'}</dd>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}
