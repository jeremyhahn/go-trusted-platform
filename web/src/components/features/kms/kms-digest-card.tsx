'use client';

/**
 * KmsDigestCard — hash text, and compute and check an HMAC, on the KMS
 * backend (#2057).
 *
 * The text is hashed by the KMS backend, not in the browser: the card sends
 * it to POST /api/v1/kms/hash through the API client and shows the digest the
 * server answers. HMAC keys are named KMS keys: the card computes a tag under
 * one at POST /api/v1/kms/hmac/{name} and checks a tag at .../verify. A
 * refusal is shown verbatim.
 */

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import {
  DIGEST_ALGORITHMS,
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

  const [macKey, setMacKey] = useState('');
  const [macText, setMacText] = useState('');
  const [macAlg, setMacAlg] = useState<DigestAlgorithm>('SHA-256');
  const [tag, setTag] = useState('');
  const [tagOut, setTagOut] = useState<string | null>(null);
  const [verdict, setVerdict] = useState<boolean | null>(null);

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

  const handleHmac = async () => {
    const name = macKey.trim();
    setBusy(true);
    try {
      const res = await digest.hmac(name, macText, macAlg);
      if (res.success && res.data) {
        const out = res.data.hmac ?? '';
        setTagOut(out);
        setTag(out);
        setVerdict(null);
        toast({ title: 'HMAC computed', description: `Key ${res.data.key_id ?? name}`, variant: 'success' });
      } else {
        refuse('HMAC failed', res.error?.message || 'The KMS did not compute an HMAC');
      }
    } catch (err) {
      refuse('HMAC failed', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const handleVerify = async () => {
    setBusy(true);
    setVerdict(null);
    try {
      const res = await digest.verifyHmac(macKey.trim(), macText, tag, macAlg);
      if (res.success && res.data) {
        setVerdict(res.data.valid === true);
      } else {
        refuse('HMAC verify failed', res.error?.message || 'The KMS did not check the HMAC');
      }
    } catch (err) {
      refuse('HMAC verify failed', errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="kms-digest-card">
      <CardHeader>
        <CardTitle>Digest and HMAC</CardTitle>
        <CardDescription>Hash text, or compute and check an HMAC with a KMS key.</CardDescription>
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
          <div className="space-y-1">
            <Label htmlFor="kms-hmac-key">Key name</Label>
            <Input
              id="kms-hmac-key"
              value={macKey}
              onChange={(e) => {
                setMacKey(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-hmac-text">Message</Label>
            <Textarea
              id="kms-hmac-text"
              value={macText}
              onChange={(e) => {
                setMacText(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-hmac-alg">HMAC hash</Label>
            <select
              id="kms-hmac-alg"
              className={SELECT_CLASS}
              value={macAlg}
              onChange={(e) => setMacAlg(e.target.value as DigestAlgorithm)}
            >
              {DIGEST_ALGORITHMS.map((a) => (
                <option key={a} value={a}>
                  {a}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-hmac-tag">Tag (base64)</Label>
            <Input
              id="kms-hmac-tag"
              value={tag}
              onChange={(e) => {
                setTag(e.target.value);
                setVerdict(null);
              }}
            />
          </div>
          <div className="flex gap-2">
            <Gated op="POST /api/v1/kms/hmac/{name}">
              <Button onClick={handleHmac} disabled={busy || macKey.trim() === ''}>
                Compute HMAC
              </Button>
            </Gated>
            <Gated op="POST /api/v1/kms/hmac/{name}/verify">
              <Button
                variant="outline"
                onClick={handleVerify}
                disabled={busy || macKey.trim() === '' || tag.trim() === ''}
              >
                Verify HMAC
              </Button>
            </Gated>
          </div>
          {tagOut !== null && (
            <code
              data-testid="kms-hmac-tag-out"
              className="block rounded bg-muted p-2 text-xs font-mono break-all"
            >{tagOut}</code>
          )}
          {verdict !== null && (
            <Badge data-testid="kms-hmac-verdict" variant={verdict ? 'default' : 'destructive'}>
              {verdict ? 'Valid' : 'Invalid'}
            </Badge>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
