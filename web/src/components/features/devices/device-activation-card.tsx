'use client';

/**
 * DeviceActivationCard — find a registered device by serial
 * (GET /api/v1/devices/serial/{serial}), then activate it (#2048).
 *
 * Activation moves the device onto its profile's admitted network, so the
 * card asks first; refusals are shown verbatim.
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
import { useToast } from '@/hooks/use-toast';
import { useDeviceActivation, type ActivationResult, type FoundDevice } from '@/hooks/use-device-activation';

function show(value: string | number | undefined): string {
  return value === undefined || value === '' ? '-' : String(value);
}

export function DeviceActivationCard(): JSX.Element {
  const api = useDeviceActivation();
  const { toast } = useToast();
  const [serial, setSerial] = useState('');
  const [busy, setBusy] = useState(false);
  const [device, setDevice] = useState<FoundDevice | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [mac, setMac] = useState('');
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [activation, setActivation] = useState<ActivationResult | null>(null);

  const handleActivate = async () => {
    if (!device?.serial) return;
    setConfirmOpen(false);
    setBusy(true);
    try {
      const res = await api.activate(device.serial, mac.trim() || undefined);
      if (res.success && res.data) {
        setActivation(res.data);
        toast({ title: 'Device activated', description: `VLAN ${res.data.vlan}`, variant: 'success' });
      } else {
        toast({
          title: 'Activation failed',
          description: res.error?.message || 'The control plane did not activate the device',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({
        title: 'Activation failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  const handleFind = async () => {
    const wanted = serial.trim();
    if (!wanted) {
      toast({ title: 'Serial number required', description: 'enter the device serial', variant: 'destructive' });
      return;
    }
    setBusy(true);
    setRefusal(null);
    setActivation(null);
    try {
      const res = await api.findBySerial(wanted);
      if (res.success && res.data) {
        setDevice(res.data);
      } else {
        setDevice(null);
        setRefusal(res.error?.message || 'The control plane found no device');
      }
    } catch (err) {
      setDevice(null);
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const switchText =
    device && (device.switch_name || device.switch_port)
      ? `${show(device.switch_name)} / ${show(device.switch_port)}`
      : '-';

  return (
    <Card data-testid="device-activation-card">
      <CardHeader>
        <CardTitle>Activate a device</CardTitle>
        <CardDescription>Find a registered device by serial, then move it onto its profile&apos;s network.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input aria-label="Serial number" value={serial} onChange={(e) => setSerial(e.target.value)} />
          <Button onClick={handleFind} disabled={busy}>
            Find
          </Button>
        </div>

        {refusal !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {refusal}
          </p>
        )}

        {device && (
          <dl data-testid="device-activation-found" className="grid grid-cols-2 gap-1 text-sm">
            <dt>ID</dt>
            <dd>{show(device.id)}</dd>
            <dt>Serial</dt>
            <dd>{show(device.serial)}</dd>
            <dt>Model</dt>
            <dd>{show(device.model)}</dd>
            <dt>State</dt>
            <dd>{show(device.state)}</dd>
            <dt>Switch</dt>
            <dd>{switchText}</dd>
            <dt>Last heartbeat</dt>
            <dd>{show(device.last_heartbeat_at)}</dd>
          </dl>
        )}

        {device && (
          <div className="flex gap-2">
            <Input aria-label="MAC address (optional)" value={mac} onChange={(e) => setMac(e.target.value)} />
            <Button onClick={() => setConfirmOpen(true)} disabled={busy}>
              Activate
            </Button>
          </div>
        )}

        {activation && (
          <div data-testid="device-activation-result" className="text-sm">
            <p>{`${activation.status} on VLAN ${activation.vlan}`}</p>
            <p className="text-muted-foreground">{show(activation.transitioned_at)}</p>
          </div>
        )}
      </CardContent>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{`Activate ${device?.serial ?? ''}?`}</DialogTitle>
            <DialogDescription>The device is moved onto the admitted VLAN of the profile that matches it.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleActivate}>Activate</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
