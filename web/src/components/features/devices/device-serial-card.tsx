'use client';

/**
 * DeviceSerialCard — edit a device's serial (#2048).
 *
 * "Save serial" calls the SDK DeviceService updateDevice, PUT
 * /api/v1/devices/{id}, with { device: { id, serial } } only. The server keeps
 * every field the request leaves zero, so the serial is the one thing that
 * changes; state and model are never sent. A serial another device holds is
 * refused with 409 (pkg/device/service.go refuseTakenSerial,
 * ErrDeviceSerialExists), shown as a destructive toast. The control sits
 * behind the capability gate; onSaved re-reads the device.
 */

import { useEffect, useState } from 'react';
import { useDevice, useMutation } from 'trusted-platform-sdk';
import type { Device } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Gated } from '@/components/features/capabilities/gated';
import { useToast } from '@/hooks/use-toast';
import { DEVICE_UPDATE_OP } from './device-model-card';

export interface DeviceSerialCardProps {
  deviceId: string;
  serial?: string;
  onSaved?: () => void;
}

export function DeviceSerialCard({ deviceId, serial, onSaved }: DeviceSerialCardProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [value, setValue] = useState(serial ?? '');

  useEffect(() => {
    setValue(serial ?? '');
  }, [serial]);

  const saveMutation = useMutation(
    // The SDK Device type requires every field; the server's Update keeps
    // the stored value of each field left out, so only id and serial go.
    (next: string) => deviceService.updateDevice({ device: { id: deviceId, serial: next } as Device }),
    {
      onSuccess: () => {
        toast({ title: 'Device updated', description: 'The serial was saved.' });
        onSaved?.();
      },
      onError: (error) => {
        toast({ title: 'Update refused', description: error.message, variant: 'destructive' });
      },
    }
  );

  const trimmed = value.trim();
  const unchanged = trimmed === '' || trimmed === (serial ?? '');

  return (
    <Card data-testid="device-serial-card">
      <CardHeader>
        <CardTitle>Serial</CardTitle>
        <CardDescription>The serial number the control plane records; no two devices share one.</CardDescription>
      </CardHeader>
      <CardContent className="flex items-end gap-2">
        <div className="flex-1 space-y-2">
          <Label htmlFor="device-serial-input">Serial</Label>
          <Input id="device-serial-input" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <Gated op={DEVICE_UPDATE_OP}>
          <Button disabled={saveMutation.isLoading || unchanged} onClick={() => saveMutation.mutate(trimmed)}>
            Save serial
          </Button>
        </Gated>
      </CardContent>
    </Card>
  );
}
