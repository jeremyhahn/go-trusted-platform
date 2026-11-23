'use client';

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Gated } from '@/components/features/capabilities/gated';
import { useToast } from '@/hooks/use-toast';
import { useVMMigration } from '@/hooks/use-vm-migration';

const PREPARE_OP = 'POST /api/v1/compute/migrations/prepare';
const FINALIZE_OP = 'POST /api/v1/compute/migrations/{receiverId}/finalize';

interface Receiver {
  receiverId: string;
  port: number;
  tlsHostname: string;
}

function errorText(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  return 'the control plane refused the migration request';
}

/**
 * MigrationsPage readies a receiver on this host for an incoming VM
 * (PrepareMigration) and commits or aborts it after a confirm
 * (FinalizeMigration), through the SDK ComputeService (useVMMigration),
 * each control behind the server's capability gate (#2044).
 */
export default function MigrationsPage() {
  const { toast } = useToast();
  const [vmId, setVmId] = useState('');
  const [vmName, setVmName] = useState('');
  const [mode, setMode] = useState<'cold' | 'live'>('cold');
  const [pending, setPending] = useState(false);
  const [receiver, setReceiver] = useState<Receiver | null>(null);
  const [confirm, setConfirm] = useState<'commit' | 'abort' | null>(null);
  const { prepare, finalize } = useVMMigration(vmId.trim());

  const fail = (message: string) => {
    toast({ title: 'Migration request failed', description: message, variant: 'destructive' });
  };

  const handlePrepare = async () => {
    const id = vmId.trim();
    const name = vmName.trim();
    if (!id || !name || pending) {
      return;
    }
    setPending(true);
    try {
      const res = await prepare({ vmId: id, vmName: name, mode });
      if (!res || res.success === false || !res.data) {
        fail(errorText(res?.error));
        return;
      }
      const { receiverId, port, tlsHostname } = res.data;
      setReceiver({ receiverId, port, tlsHostname });
      toast({ title: 'Receiver prepared', description: `Receiver ${receiverId} is ready`, variant: 'success' });
    } catch (err) {
      fail(errorText(err));
    } finally {
      setPending(false);
    }
  };

  const handleFinalize = async (commit: boolean) => {
    if (!receiver || pending) {
      return;
    }
    setPending(true);
    try {
      const res = await finalize(receiver.receiverId, commit);
      if (res && res.success === false) {
        fail(errorText(res.error));
        return;
      }
      toast({
        title: commit ? 'Migration committed' : 'Migration aborted',
        description: `Receiver ${receiver.receiverId}`,
        variant: 'success',
      });
      setConfirm(null);
      setReceiver(null);
    } catch (err) {
      fail(errorText(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Migrations</h1>
        <p className="text-muted-foreground mt-1">
          Prepare a receiver for an incoming VM, then commit or abort the migration
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Prepare receiver</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="migration-vm-id">VM ID</Label>
            <Input
              id="migration-vm-id"
              aria-label="VM ID"
              value={vmId}
              onChange={(e) => setVmId(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="migration-vm-name">VM name</Label>
            <Input
              id="migration-vm-name"
              aria-label="VM name"
              value={vmName}
              onChange={(e) => setVmName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="migration-mode">Mode</Label>
            <select
              id="migration-mode"
              aria-label="Mode"
              className="border-input bg-background h-9 w-full rounded-md border px-3 text-sm"
              value={mode}
              onChange={(e) => setMode(e.target.value === 'live' ? 'live' : 'cold')}
            >
              <option value="cold">cold</option>
              <option value="live">live</option>
            </select>
          </div>
          <Gated op={PREPARE_OP}>
            <Button onClick={handlePrepare} disabled={!vmId.trim() || !vmName.trim() || pending}>
              Prepare receiver
            </Button>
          </Gated>

          {receiver && (
            <div data-testid="migration-receiver" className="space-y-2 rounded-md border p-4 text-sm">
              <div>
                <span className="text-muted-foreground">Receiver: </span>
                <span className="font-mono">{receiver.receiverId}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Port: </span>
                <span className="font-mono">{receiver.port}</span>
              </div>
              <div>
                <span className="text-muted-foreground">TLS hostname: </span>
                <span className="font-mono">{receiver.tlsHostname}</span>
              </div>
              <div className="flex gap-2 pt-2">
                <Gated op={FINALIZE_OP}>
                  <Button variant="outline" onClick={() => setConfirm('commit')} disabled={pending}>
                    Commit
                  </Button>
                </Gated>
                <Gated op={FINALIZE_OP}>
                  <Button variant="outline" onClick={() => setConfirm('abort')} disabled={pending}>
                    Abort
                  </Button>
                </Gated>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={confirm !== null}
        onOpenChange={(next) => {
          if (!next) {
            setConfirm(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirm === 'abort' ? 'Abort migration?' : 'Commit migration?'}</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            {confirm === 'abort'
              ? 'The receiver discards the incoming VM.'
              : 'The receiver keeps the migrated VM and the source releases it.'}
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirm(null)} disabled={pending}>
              Cancel
            </Button>
            {confirm === 'abort' ? (
              <Button variant="destructive" onClick={() => handleFinalize(false)} disabled={pending}>
                Abort
              </Button>
            ) : (
              <Button onClick={() => handleFinalize(true)} disabled={pending}>
                Commit
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
