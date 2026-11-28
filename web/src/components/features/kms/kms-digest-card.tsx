'use client';

/**
 * KmsDigestCard — hash text on the KMS backend (#2057).
 *
 * The text is hashed by the KMS backend, not in the browser: the card sends
 * it to POST /api/v1/kms/hash through the API client and shows the digest the
 * server answers. A refusal is shown verbatim.
 *
 * HMAC generate and verify are withheld (#2180 round 9): the backend makes a
 * fresh MAC key per call, so a tag it computes never verifies. The card says
 * so and offers no HMAC control until the backend uses a stable MAC key.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import {
  DIGEST_ALGORITHMS,
  HMAC_UNAVAILABLE,
  useKmsDigest,
  type DigestAlgorithm,
  type KmsHashResult,
} from '@/hooks/use-kms-digest';

const SELECT_CLASS =
  'flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function KmsDigestCard(): JSX.Element {
  const digest = useKmsDigest();
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);

  const [text, setText] = useState('');
  const [alg, setAlg] = useState<DigestAlgorithm>('SHA-256');
  const [hashResult, setHashResult] = useState<KmsHashResult | null>(null);

  const refuse = (title: string, description: string) =>
    toast({ title, description, variant: 'destructive' });

  const handleHash = async () => {
    setBusy(true);
    try {
      const res = await digest.hash(text, alg);
      if (res.success && res.data) {
        setHashResult(res.data);
      } else {
        setHashResult(null);
        refuse('Hash failed', res.error?.message || 'The KMS did not hash the text');
      }
    } catch (err) {
      setHashResult(null);
      refuse('Hash failed', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="kms-digest-card">
      <CardHeader>
        <CardTitle>Digest and HMAC</CardTitle>
        <CardDescription>Hash text with the KMS backend.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3">
          <h3 className="text-sm font-medium">Hash</h3>
          <div className="space-y-1">
            <Label htmlFor="kms-hash-text">Text to hash</Label>
            <Textarea id="kms-hash-text" value={text} onChange={(e) => setText(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-hash-alg">Hash algorithm</Label>
            <select
              id="kms-hash-alg"
              className={SELECT_CLASS}
              value={alg}
              onChange={(e) => setAlg(e.target.value as DigestAlgorithm)}
            >
              {DIGEST_ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <Gated op="POST /api/v1/kms/hash">
            <Button onClick={handleHash} disabled={busy || text === ''}>
              Hash
            </Button>
          </Gated>
          {hashResult && (
            <dl data-testid="kms-hash-result" className="space-y-1 text-sm">
              <dt className="font-medium">Algorithm</dt>
              <dd>{hashResult.hash}</dd>
              <dt className="font-medium">Digest (base64)</dt>
              <dd>
                <code className="block rounded bg-muted p-2 text-xs font-mono break-all">
                  {hashResult.digest}
                </code>
              </dd>
            </dl>
          )}
        </section>

        <section className="space-y-3">
          <h3 className="text-sm font-medium">HMAC</h3>
          <p data-testid="kms-hmac-withheld" className="text-sm text-muted-foreground">
            {HMAC_UNAVAILABLE}.
          </p>
        </section>
      </CardContent>
    </Card>
  );
}
