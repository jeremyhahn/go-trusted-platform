'use client';

/**
 * WrappedDataKeyCard: KMS GenerateWrappedDataKey
 * (`POST /api/v1/kms/data-keys/wrapped`) through useKMSDataKeys. The
 * plaintext never leaves the service; only the wrapped key is shown.
 * A refusal is shown verbatim.
 */

import { useState } from 'react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useKMSDataKeys, type KMSWrappedDataKey } from '@/hooks/use-kms-data-keys';

export function WrappedDataKeyCard() {
  const { generateWrappedDataKey } = useKMSDataKeys();
  const { toast } = useToast();
  const [wrappingKeyId, setWrappingKeyId] = useState('');
  const [context, setContext] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<KMSWrappedDataKey | null>(null);

  const generate = async () => {
    setBusy(true);
    try {
      const res = await generateWrappedDataKey(wrappingKeyId, context);
      if (res.success && res.data) {
        const data = res.data;
        setResult(data);
        toast({
          title: 'Wrapped data key generated',
          description: `under ${data.wrapping_key_id}`,
          variant: 'success',
        });
      } else {
        setResult(null);
        toast({
          title: 'Generate wrapped data key failed',
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Generate wrapped data key</CardTitle>
        <CardDescription>
          A data key wrapped under a KMS key; the plaintext never leaves the service.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="grid gap-2">
          <Label htmlFor="wrapping-key-id">Wrapping key ID</Label>
          <Input
            id="wrapping-key-id"
            aria-label="Wrapping key ID"
            value={wrappingKeyId}
            onChange={(e) => setWrappingKeyId(e.target.value)}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="wrapping-context">Wrapping context</Label>
          <Input
            id="wrapping-context"
            aria-label="Wrapping context"
            placeholder="optional"
            value={context}
            onChange={(e) => setContext(e.target.value)}
          />
        </div>
        <div>
          <Button disabled={busy || wrappingKeyId.trim() === ''} onClick={generate}>
            Generate wrapped data key
          </Button>
        </div>
        {result && (
          <div className="flex flex-col gap-2">
            <p className="text-sm text-muted-foreground">Wrapped under {result.wrapping_key_id}</p>
            <code data-testid="wrapped-key" className="break-all">
              {result.wrapped_key}
            </code>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
