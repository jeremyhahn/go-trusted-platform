'use client';

/**
 * TPMKeyLifecycleCard — creates and evicts the TPM's endorsement key and
 * imports its certificate, and creates and evicts the storage root key
 * (#2068), on the SDK TPMService through useTPMKeyLifecycle.
 *
 * Evicting a key removes it from the TPM, so the card asks first. The control
 * plane's refusals are shown verbatim: their text names what was refused.
 */

import { useState } from 'react';
import type { ApiResponse } from 'trusted-platform-sdk';
import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useToast } from '@/hooks/use-toast';
import { parseHandle, useTPMKeyLifecycle } from '@/hooks/use-tpm-key-lifecycle';
import { textToBase64 } from '@/hooks/use-tpm-ops';

type Confirm = 'ek' | 'srk' | null;

const CONFIRM_TEXT: Record<'ek' | 'srk', { title: string; description: string }> = {
  ek: {
    title: 'Evict the EK?',
    description:
      'The endorsement key is removed from the TPM; attestation that uses it stops until a new one is created.',
  },
  srk: {
    title: 'Evict the SRK?',
    description: 'The storage root key is removed from the TPM; keys sealed under it can no longer be loaded.',
  },
};

export function TPMKeyLifecycleCard(): JSX.Element {
  const { createEK, deleteEK, importEKCertificate, createSRK, deleteSRK } = useTPMKeyLifecycle();
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const [handle, setHandle] = useState('');
  const [pem, setPem] = useState('');
  const [lastHandle, setLastHandle] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Confirm>(null);
  const [confirmHandle, setConfirmHandle] = useState<number | undefined>(undefined);

  const run = async (
    title: string,
    call: () => Promise<ApiResponse<{ status?: { message?: string }; handle?: number }>>
  ) => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success) {
        toast({ title, description: res.data?.status?.message ?? 'done', variant: 'success' });
        if (typeof res.data?.handle === 'number') {
          setLastHandle(`0x${res.data.handle.toString(16)}`);
        }
      } else {
        toast({ title: `${title} failed`, description: res.error?.message, variant: 'destructive' });
      }
    } catch (err) {
      toast({
        title: `${title} failed`,
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  const askEvict = (key: 'ek' | 'srk') => {
    const parsed = parseHandle(handle);
    if (Number.isNaN(parsed)) {
      toast({
        title: 'Invalid handle',
        description: 'a handle is a hex (0x...) or decimal number',
        variant: 'destructive',
      });
      return;
    }
    setConfirmHandle(parsed);
    setConfirm(key);
  };

  const evict = () => {
    const key = confirm;
    const parsed = confirmHandle;
    setConfirm(null);
    // The handle is optional on the wire: without one the server evicts the
    // key at its configured handle.
    const req = (parsed === undefined ? {} : { handle: parsed }) as { handle: number };
    if (key === 'ek') {
      void run('EK evicted', () => deleteEK(req));
    } else if (key === 'srk') {
      void run('SRK evicted', () => deleteSRK(req));
    }
  };

  const importCertificate = () => {
    const text = pem.trim();
    if (text === '') {
      toast({ title: 'Certificate required', description: 'paste the PEM certificate', variant: 'destructive' });
      return;
    }
    void run('EK certificate imported', () =>
      importEKCertificate({ certificate: textToBase64(text), format: 'PEM' })
    );
  };

  return (
    <Card data-testid="tpm-key-lifecycle-card">
      <CardHeader>
        <CardTitle>TPM keys</CardTitle>
        <CardDescription>Create or evict the endorsement and storage root keys.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {lastHandle !== null && (
          <p className="text-sm" data-testid="tpm-last-handle">
            Last handle: <code className="font-mono">{lastHandle}</code>
          </p>
        )}
        <div className="space-y-2">
          <Label htmlFor="tpm-key-handle">Handle</Label>
          <Input
            id="tpm-key-handle"
            aria-label="Key handle"
            placeholder="0x81010001"
            value={handle}
            onChange={(e) => setHandle(e.target.value)}
            disabled={busy}
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <Gated op="POST /api/v1/tpm/ek">
            <Button onClick={() => void run('EK created', () => createEK({ persistent: true }))} disabled={busy}>
              Create EK
            </Button>
          </Gated>
          <Gated op="DELETE /api/v1/tpm/ek">
            <Button variant="destructive" onClick={() => askEvict('ek')} disabled={busy}>
              Evict EK
            </Button>
          </Gated>
          <Gated op="POST /api/v1/tpm/srk">
            <Button onClick={() => void run('SRK created', () => createSRK({ persistent: true }))} disabled={busy}>
              Create SRK
            </Button>
          </Gated>
          <Gated op="DELETE /api/v1/tpm/srk">
            <Button variant="destructive" onClick={() => askEvict('srk')} disabled={busy}>
              Evict SRK
            </Button>
          </Gated>
        </div>
        <div className="space-y-2">
          <Label htmlFor="tpm-ek-certificate">EK certificate</Label>
          <Textarea
            id="tpm-ek-certificate"
            aria-label="EK certificate (PEM)"
            placeholder="-----BEGIN CERTIFICATE-----"
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            disabled={busy}
            className="font-mono text-xs"
          />
          <Gated op="POST /api/v1/tpm/ek/certificate">
            <Button variant="outline" onClick={importCertificate} disabled={busy}>
              Import certificate
            </Button>
          </Gated>
        </div>
      </CardContent>

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        <DialogContent>
          {confirm !== null && (
            <>
              <DialogHeader>
                <DialogTitle>{CONFIRM_TEXT[confirm].title}</DialogTitle>
                <DialogDescription>{CONFIRM_TEXT[confirm].description}</DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button variant="outline" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button variant="destructive" onClick={evict}>
                  Evict
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}
