'use client';

import { useState } from 'react';
import { BadgeCheck, RotateCw, ShieldAlert, ShieldCheck, Trash2 } from 'lucide-react';
import type { ApiResponse, PXEDeviceInfo } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Gated } from '@/components/features/capabilities/gated';
import { usePXE, useToast } from '@/hooks';

const AUTHORIZE_OP = 'POST /api/v1/pxe/devices/{id}/authorize';
const QUARANTINE_OP = 'POST /api/v1/pxe/devices/{id}/quarantine';
const RETRY_OP = 'POST /api/v1/pxe/devices/{id}/retry';
const REMOVE_OP = 'DELETE /api/v1/pxe/devices/{id}';
const ENROLLED_OP = 'POST /api/v1/pxe/devices/{id}/enrolled';

type Pending = 'authorize' | 'quarantine' | 'remove' | 'enrolled' | null;

export interface PXEDeviceActionsProps {
  device: Pick<PXEDeviceInfo, 'id' | 'macAddress' | 'state'>;
  onChanged: () => void;
}

/**
 * PXEDeviceActions is the row control set of the PXE devices table: each
 * action is gated on the server route it calls and goes through the SDK
 * PXEService.
 */
export function PXEDeviceActions({ device, onChanged }: PXEDeviceActionsProps) {
  const pxe = usePXE();
  const { toast } = useToast();
  const [pending, setPending] = useState<Pending>(null);
  const [busy, setBusy] = useState(false);
  const [targetVlan, setTargetVlan] = useState('');
  const [reason, setReason] = useState('');
  const [certificateSerial, setCertificateSerial] = useState('');
  const id = device.id;

  const write = async (title: string, call: () => Promise<ApiResponse<unknown>>): Promise<void> => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success === false) {
        toast({
          title: 'PXE request failed',
          description: res.error?.message,
          variant: 'destructive',
        });
        return;
      }
      toast({ title, description: `${device.macAddress}`, variant: 'success' });
      setPending(null);
      setTargetVlan('');
      setReason('');
      setCertificateSerial('');
      onChanged();
    } catch (err) {
      toast({
        title: 'PXE request failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  const authorize = () => {
    const vlan = targetVlan.trim() === '' ? undefined : Number(targetVlan);
    return write('Device authorized', () => pxe.authorizeDevice({ deviceId: id, targetVlan: vlan }));
  };
  const quarantine = () =>
    write('Device quarantined', () =>
      pxe.quarantineDevice({ deviceId: id, reason: reason.trim() === '' ? undefined : reason.trim() }),
    );
  const retry = () => write('Device retry started', () => pxe.retryDevice(id));
  const remove = () => write('Device removed', () => pxe.removeDevice(id));
  const markEnrolled = () =>
    write('Device marked enrolled', () =>
      pxe.setDeviceEnrolled({ deviceId: id, certificateSerial: certificateSerial.trim() }),
    );

  const close = (open: boolean) => {
    if (!open) setPending(null);
  };

  return (
    <div className="flex justify-end gap-1">
      <Gated op={AUTHORIZE_OP}>
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Authorize ${id}`}
          disabled={busy}
          onClick={() => setPending('authorize')}
        >
          <ShieldCheck className="h-4 w-4" />
        </Button>
      </Gated>
      <Gated op={QUARANTINE_OP}>
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Quarantine ${id}`}
          disabled={busy}
          onClick={() => setPending('quarantine')}
        >
          <ShieldAlert className="h-4 w-4" />
        </Button>
      </Gated>
      <Gated op={RETRY_OP}>
        <Button variant="ghost" size="icon" aria-label={`Retry ${id}`} disabled={busy} onClick={() => void retry()}>
          <RotateCw className="h-4 w-4" />
        </Button>
      </Gated>
      <Gated op={REMOVE_OP}>
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Remove ${id}`}
          disabled={busy}
          onClick={() => setPending('remove')}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </Gated>
      <Gated op={ENROLLED_OP}>
        <Button
          variant="ghost"
          size="icon"
          aria-label={`Mark enrolled ${id}`}
          disabled={busy}
          onClick={() => setPending('enrolled')}
        >
          <BadgeCheck className="h-4 w-4" />
        </Button>
      </Gated>

      <Dialog open={pending === 'authorize'} onOpenChange={close}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Authorize device</DialogTitle>
            <DialogDescription>
              Authorize {device.macAddress} to boot. The target VLAN is optional.
            </DialogDescription>
          </DialogHeader>
          <Input
            aria-label="Target VLAN"
            type="number"
            min={1}
            max={4094}
            placeholder="Target VLAN"
            value={targetVlan}
            onChange={(e) => setTargetVlan(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={() => void authorize()} disabled={busy}>
              Authorize
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pending === 'quarantine'} onOpenChange={close}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Quarantine device</DialogTitle>
            <DialogDescription>Quarantine {device.macAddress}; it will not boot until authorized again.</DialogDescription>
          </DialogHeader>
          <Input
            aria-label="Quarantine reason"
            placeholder="Reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void quarantine()} disabled={busy}>
              Quarantine
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pending === 'remove'} onOpenChange={close}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Remove device</DialogTitle>
            <DialogDescription>Remove {device.macAddress} from the PXE inventory.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void remove()} disabled={busy}>
              Remove
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={pending === 'enrolled'} onOpenChange={close}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark device enrolled</DialogTitle>
            <DialogDescription>
              Mark {device.macAddress} enrolled with the serial of the certificate it was issued.
            </DialogDescription>
          </DialogHeader>
          <Input
            aria-label="Certificate serial"
            placeholder="Certificate serial"
            value={certificateSerial}
            onChange={(e) => setCertificateSerial(e.target.value)}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)} disabled={busy}>
              Cancel
            </Button>
            <Button onClick={() => void markEnrolled()} disabled={busy || certificateSerial.trim() === ''}>
              Mark enrolled
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
