'use client';

/**
 * KmsKeyAdminCard — change a KMS key's status (UpdateKeyStatus, #2057).
 *
 * A disabled or compromised key refuses every operation, so every status but
 * ENABLED asks first. A refusal from the control plane is toasted verbatim.
 */

import { useState } from 'react';
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
import { useToast } from '@/hooks';
import { KEY_STATUSES, useKmsKeyAdmin, type KeyStatus } from '@/hooks/use-kms-key-admin';

const SELECT_CLASS =
  'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring';

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function KmsKeyAdminCard(): JSX.Element {
  const admin = useKmsKeyAdmin();
  const { toast } = useToast();

  const [key, setKey] = useState('');
  const [status, setStatus] = useState<KeyStatus>('ENABLED');
  const [versionText, setVersionText] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  const runStatus = async () => {
    const name = key.trim();
    const version = versionText.trim() !== '' ? Number(versionText) : undefined;
    setBusy(true);
    try {
      const res = await admin.setStatus(name, status, version);
      if (res.success && res.data) {
        const data = res.data;
        toast({
          title: 'Key status updated',
          description: `${data.key_id} v${data.version} is ${data.status}`,
          variant: 'success',
        });
      } else {
        toast({
          title: 'Status update failed',
          description: res.error?.message || 'The control plane did not update the status',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Status update failed', description: errorMessage(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const onUpdateStatus = () => {
    if (status === 'ENABLED') {
      void runStatus();
    } else {
      setConfirmOpen(true);
    }
  };

  const onConfirm = () => {
    setConfirmOpen(false);
    void runStatus();
  };

  return (
    <Card data-testid="kms-key-admin-card">
      <CardHeader>
        <CardTitle>Key administration</CardTitle>
        <CardDescription>Change a key&apos;s status, or import key material as a new key.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3" aria-labelledby="kms-status-heading">
          <h3 id="kms-status-heading" className="text-sm font-medium">
            Status
          </h3>
          <div className="space-y-1">
            <Label htmlFor="kms-status-key">Key name</Label>
            <Input id="kms-status-key" value={key} onChange={(e) => setKey(e.target.value)} />
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-status-value">New status</Label>
            <select
              id="kms-status-value"
              className={SELECT_CLASS}
              value={status}
              onChange={(e) => setStatus(e.target.value as KeyStatus)}
            >
              {KEY_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1">
            <Label htmlFor="kms-status-version">Version (optional)</Label>
            <Input
              id="kms-status-version"
              type="number"
              min={1}
              value={versionText}
              onChange={(e) => setVersionText(e.target.value)}
            />
          </div>
          <Button onClick={onUpdateStatus} disabled={busy || key.trim() === ''}>
            Update status
          </Button>
        </section>
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{`Set ${key.trim()} to ${status}?`}</DialogTitle>
            <DialogDescription>
              {`Operations with this key are refused while it is ${status}.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={onConfirm}>
              Set status
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
