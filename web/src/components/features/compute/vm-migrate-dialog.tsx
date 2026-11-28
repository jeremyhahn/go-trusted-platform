'use client';

import { useState } from 'react';
import { ArrowRightLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Gated } from '@/components/features/capabilities/gated';
import { useToast } from '@/hooks/use-toast';
import { useVMMigration } from '@/hooks/use-vm-migration';

export interface VMMigrateButtonProps {
  vmId: string;
  disabled?: boolean;
  /**
   * When set, the guest cannot be migrated (for example it has a vTPM, whose
   * state migration does not carry): Migrate is disabled and this is shown.
   */
  unsupportedReason?: string;
  onMigrated: () => void;
}

function errorText(err: unknown): string {
  if (typeof err === 'string') {
    return err;
  }
  if (err && typeof err === 'object' && 'message' in err && typeof err.message === 'string') {
    return err.message;
  }
  return 'the control plane refused the migration';
}

/**
 * VMMigrateButton opens a dialog that sends MigrateVM through the SDK
 * ComputeService (useVMMigration), behind the server's capability gate (#2044).
 */
export function VMMigrateButton({ vmId, disabled, unsupportedReason, onMigrated }: VMMigrateButtonProps) {
  const { toast } = useToast();
  const { migrate } = useVMMigration(vmId);
  const [open, setOpen] = useState(false);
  const [host, setHost] = useState('');
  const [live, setLive] = useState(false);
  const [bandwidth, setBandwidth] = useState('');
  const [pending, setPending] = useState(false);

  const reset = () => {
    setHost('');
    setLive(false);
    setBandwidth('');
  };

  const fail = (message: string) => {
    toast({ title: 'Migration failed', description: message, variant: 'destructive' });
  };

  const handleStart = async () => {
    const destination = host.trim();
    if (!destination || pending) {
      return;
    }
    setPending(true);
    try {
      const res = await migrate(destination, live, bandwidth.trim() ? Number(bandwidth) : undefined);
      if (res && res.success === false) {
        fail(errorText(res.error));
        return;
      }
      toast({ title: 'Migration started', description: `Migrating to ${destination}`, variant: 'success' });
      setOpen(false);
      reset();
      onMigrated();
    } catch (err) {
      fail(errorText(err));
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <Gated op="POST /api/v1/compute/vms/{id}/migrate">
        <Button
          variant="outline"
          onClick={() => setOpen(true)}
          disabled={disabled || !!unsupportedReason}
          title={unsupportedReason}
        >
          <ArrowRightLeft className="mr-2 h-4 w-4" />
          Migrate
        </Button>
      </Gated>
      {unsupportedReason ? <p className="text-xs text-muted-foreground">{unsupportedReason}</p> : null}
      <Dialog
        open={open}
        onOpenChange={(next) => {
          setOpen(next);
          if (!next) {
            reset();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Migrate VM</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="migrate-vm-host">Destination host</Label>
              <Input
                id="migrate-vm-host"
                aria-label="Destination host"
                value={host}
                onChange={(e) => setHost(e.target.value)}
              />
            </div>
            <div className="flex items-center gap-2">
              <input
                id="migrate-vm-live"
                type="checkbox"
                aria-label="Live migration"
                checked={live}
                onChange={(e) => setLive(e.target.checked)}
              />
              <Label htmlFor="migrate-vm-live">Live migration</Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="migrate-vm-bandwidth">Bandwidth limit (Mbps)</Label>
              <Input
                id="migrate-vm-bandwidth"
                type="number"
                min={0}
                aria-label="Bandwidth limit (Mbps)"
                value={bandwidth}
                onChange={(e) => setBandwidth(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button onClick={handleStart} disabled={!host.trim() || pending}>
              Start migration
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
