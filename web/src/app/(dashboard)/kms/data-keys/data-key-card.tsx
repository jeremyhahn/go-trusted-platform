'use client';

/**
 * DataKeyCard: KMS GenerateDataKey (`POST /api/v1/kms/data-keys`) through
 * useKMSDataKeys. A refusal is shown verbatim.
 *
 * The plaintext key is secret: it is shown once, held in component state
 * only until Hide, and never stored, logged or toasted.
 */

import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { base64ByteLength, useKMSDataKeys, type KMSDataKey } from '@/hooks/use-kms-data-keys';

type ShownDataKey = Omit<KMSDataKey, 'plaintext_key'> & { plaintext_key?: string };

export function DataKeyCard() {
  const { generateDataKey } = useKMSDataKeys();
  const { toast } = useToast();
  const [keyId, setKeyId] = useState('');
  const [context, setContext] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ShownDataKey | null>(null);

  const generate = async () => {
    setBusy(true);
    try {
      const res = await generateDataKey(keyId, context);
      if (res.success && res.data) {
        const data = res.data;
        setResult(data);
        toast({ title: 'Data key generated', description: `under ${data.key_id}`, variant: 'success' });
      } else {
        setResult(null);
        toast({
          title: 'Generate data key failed',
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const hide = () => {
    setResult((r) => (r ? { key_id: r.key_id, encrypted_key: r.encrypted_key } : r));
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Generate data key</CardTitle>
        <CardDescription>
          A 256-bit data key under a KMS key: the plaintext and its encrypted copy.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-2">
          <Label htmlFor="data-key-id">Key ID</Label>
          <Input
            id="data-key-id"
            aria-label="Key ID"
            value={keyId}
            onChange={(e) => setKeyId(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="data-key-context">Encryption context</Label>
          <Input
            id="data-key-context"
            aria-label="Encryption context"
            placeholder="optional"
            value={context}
            onChange={(e) => setContext(e.target.value)}
          />
        </div>
        <div>
          <Button disabled={busy || keyId.trim() === ''} onClick={generate}>
            Generate data key
          </Button>
        </div>
        {result && (
          <div className="flex flex-col gap-2">
            {result.plaintext_key !== undefined && (
              <div className="flex flex-col gap-2">
                <Label>Plaintext key</Label>
                <code data-testid="data-key-plaintext" className="break-all">
                  {result.plaintext_key}
                </code>
                <p data-testid="data-key-size" className="text-sm text-muted-foreground">
                  {base64ByteLength(result.plaintext_key) * 8}-bit key
                </p>
                <p className="text-sm text-muted-foreground">
                  Shown once. Copy it now; it is not stored.
                </p>
                <div>
                  <Button variant="outline" onClick={hide}>
                    Hide
                  </Button>
                </div>
              </div>
            )}
            <Label>Encrypted key</Label>
            <code data-testid="data-key-encrypted" className="break-all">
              {result.encrypted_key}
            </code>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
