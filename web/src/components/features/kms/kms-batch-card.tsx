'use client';

/**
 * KmsBatchCard — BatchEncrypt, BatchDecrypt and Rewrap on the KMS backend
 * (#2057).
 *
 * The card calls the SDK KMSService (useKMS): batch-encrypt sends one item per
 * line of text, base64-encoded; batch-decrypt sends one `ciphertext [nonce]`
 * pair per line and shows each plaintext decoded; rewrap re-encrypts one
 * ciphertext under the key's current version. Each control is wrapped in the
 * capability gate on the route it calls. A refusal is shown verbatim.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useKMS } from '@/hooks';
import { useToast } from '@/hooks/use-toast';
import { toBase64 } from '@/hooks/use-kms-digest';

interface ItemResult {
  item_id: string;
  ciphertext?: string;
  nonce?: string;
  plaintext?: string;
  error?: string;
}

interface BatchOutcome {
  results: ItemResult[];
  success_count: number;
  failure_count: number;
}

interface RewrapOutcome {
  dest_key_version?: number;
  ciphertext: string;
  nonce?: string;
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// The plaintext the KMS answers is base64; show it as UTF-8 text when it
// decodes as such, else as the base64 it came in.
function decodeText(b64: string): string {
  try {
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return b64;
  }
}

function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l !== '');
}

const itemId = (i: number) => `item-${i + 1}`;

export function KmsBatchCard(): JSX.Element {
  const kms = useKMS();
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);

  const [keyName, setKeyName] = useState('');
  const [items, setItems] = useState('');
  const [batch, setBatch] = useState<BatchOutcome | null>(null);

  const [ciphertext, setCiphertext] = useState('');
  const [nonce, setNonce] = useState('');
  const [rewrapped, setRewrapped] = useState<RewrapOutcome | null>(null);

  const refuse = (description: string) =>
    toast({ title: 'KMS request failed', description, variant: 'destructive' });

  const run = async <T,>(
    call: () => Promise<{ success: boolean; data?: T; error?: { message?: string } }>,
    done: (data: T) => void,
  ) => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success && res.data) {
        done(res.data);
      } else {
        refuse(res.error?.message || 'The KMS refused the request');
      }
    } catch (err) {
      refuse(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const key = keyName.trim();

  const handleEncrypt = () => {
    setBatch(null);
    return run(
      () =>
        kms.batchEncrypt({
          keyId: key,
          items: lines(items).map((l, i) => ({ itemId: itemId(i), plaintext: toBase64(l) })),
        }),
      (data) => setBatch(data),
    );
  };

  const handleDecrypt = () => {
    setBatch(null);
    return run(
      () =>
        kms.batchDecrypt({
          keyId: key,
          items: lines(items).map((l, i) => {
            const [ct, n] = l.split(/\s+/);
            return n ? { itemId: itemId(i), ciphertext: ct, nonce: n } : { itemId: itemId(i), ciphertext: ct };
          }),
        }),
      (data) => setBatch(data),
    );
  };

  const handleRewrap = () => {
    setRewrapped(null);
    const sourceNonce = nonce.trim();
    return run(
      () =>
        kms.rewrap(
          sourceNonce
            ? { sourceKeyId: key, ciphertext: ciphertext.trim(), sourceNonce }
            : { sourceKeyId: key, ciphertext: ciphertext.trim() },
        ),
      (data) => setRewrapped(data),
    );
  };

  const noItems = lines(items).length === 0;

  return (
    <Card data-testid="kms-batch-card">
      <CardHeader>
        <CardTitle>Batch and rewrap</CardTitle>
        <CardDescription>
          Encrypt or decrypt many items under one KMS key, or re-encrypt a ciphertext under the key&apos;s current
          version.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-1">
          <Label htmlFor="kms-batch-key">Key name</Label>
          <Input id="kms-batch-key" value={keyName} onChange={(e) => setKeyName(e.target.value)} />
        </div>

        <section className="space-y-3">
          <h3 className="text-sm font-medium">Batch</h3>
          <div className="space-y-1">
            <Label htmlFor="kms-batch-items">Items (one per line)</Label>
            <Textarea
              id="kms-batch-items"
              placeholder="plaintext to encrypt, or: ciphertext nonce"
              value={items}
              onChange={(e) => setItems(e.target.value)}
            />
          </div>
          <div className="flex gap-2">
            <Gated op="POST /api/v1/kms/batch-encrypt">
              <Button onClick={handleEncrypt} disabled={busy || key === '' || noItems}>
                Batch encrypt
              </Button>
            </Gated>
            <Gated op="POST /api/v1/kms/batch-decrypt">
              <Button variant="outline" onClick={handleDecrypt} disabled={busy || key === '' || noItems}>
                Batch decrypt
              </Button>
            </Gated>
          </div>
          {batch && (
            <div data-testid="kms-batch-results" className="space-y-2">
              <p className="text-sm">{`${batch.success_count} succeeded, ${batch.failure_count} failed`}</p>
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left">
                    <th className="font-medium">Item</th>
                    <th className="font-medium">Result</th>
                    <th className="font-medium">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {batch.results.map((r) => (
                    <tr key={r.item_id}>
                      <td>{r.item_id}</td>
                      <td>
                        {r.plaintext !== undefined ? (
                          <code className="break-all font-mono text-xs">{decodeText(r.plaintext)}</code>
                        ) : r.ciphertext !== undefined ? (
                          <span className="space-x-2">
                            <code className="break-all font-mono text-xs">{r.ciphertext}</code>
                            {r.nonce && <code className="break-all font-mono text-xs">{r.nonce}</code>}
                          </span>
                        ) : null}
                      </td>
                      <td>{r.error ?? ''}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="space-y-3">
          <h3 className="text-sm font-medium">Rewrap</h3>
          <div className="space-y-1">
            <Label htmlFor="kms-rewrap-ciphertext">Ciphertext</Label>
            <Input id="kms-rewrap-ciphertext" value={ciphertext} onChange={(e) => setCiphertext(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-rewrap-nonce">Nonce (optional)</Label>
            <Input id="kms-rewrap-nonce" value={nonce} onChange={(e) => setNonce(e.target.value)} />
          </div>
          <Gated op="POST /api/v1/kms/rewrap">
            <Button onClick={handleRewrap} disabled={busy || key === '' || ciphertext.trim() === ''}>
              Rewrap
            </Button>
          </Gated>
          {rewrapped && (
            <dl data-testid="kms-rewrap-result" className="space-y-1 text-sm">
              <dt className="font-medium">Key version</dt>
              <dd data-testid="kms-rewrap-version">{rewrapped.dest_key_version ?? 'not reported'}</dd>
              <dt className="font-medium">Ciphertext (base64)</dt>
              <dd>
                <code className="block rounded bg-muted p-2 text-xs font-mono break-all">{rewrapped.ciphertext}</code>
              </dd>
              {rewrapped.nonce && (
                <>
                  <dt className="font-medium">Nonce (base64)</dt>
                  <dd>
                    <code className="block rounded bg-muted p-2 text-xs font-mono break-all">{rewrapped.nonce}</code>
                  </dd>
                </>
              )}
            </dl>
          )}
        </section>
      </CardContent>
    </Card>
  );
}
