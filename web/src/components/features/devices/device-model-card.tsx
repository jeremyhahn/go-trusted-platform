'use client';

/**
 * DeviceModelCard — edit a device's model (#2048).
 *
 * "Save" calls the SDK DeviceService updateDevice, PUT /api/v1/devices/{id},
 * with { device: { id, model } } only. The server keeps every field the
 * request leaves zero, so the model is the one thing that changes; state is
 * never sent, Enable and Disable stay on the lifecycle transitions (#250).
 * The control sits behind the capability gate. The response is not read:
 * onSaved re-reads the device. A refusal is shown as a destructive toast.
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

export const DEVICE_UPDATE_OP = 'PUT /api/v1/devices/{id:[0-9]+}';

export interface DeviceModelCardProps {
  deviceId: string;
  model?: string;
  onSaved?: () => void;
}

export function DeviceModelCard({ deviceId, model, onSaved }: DeviceModelCardProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [value, setValue] = useState(model ?? '');

  useEffect(() => {
    setValue(model ?? '');
  }, [model]);

  const saveMutation = useMutation(
    // The SDK Device type requires every field; the server's Update keeps
    // the stored value of each field left out, so only id and model go.
    (next: string) => deviceService.updateDevice({ device: { id: deviceId, model: next } as Device }),
    {
      onSuccess: () => {
        toast({ title: 'Device updated', description: 'The model was saved.' });
        onSaved?.();
      },
      onError: (error) => {
        toast({ title: 'Update refused', description: error.message, variant: 'destructive' });
      },
    }
  );

  const trimmed = value.trim();
  const unchanged = trimmed === '' || trimmed === (model ?? '');

  return (
    <Card data-testid="device-model-card">
      <CardHeader>
        <CardTitle>Model</CardTitle>
        <CardDescription>The device model the control plane records.</CardDescription>
      </CardHeader>
      <CardContent className="flex items-end gap-2">
        <div className="flex-1 space-y-2">
          <Label htmlFor="device-model-input">Model</Label>
          <Input id="device-model-input" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <Gated op={DEVICE_UPDATE_OP}>
          <Button data-testid="device-model-save" disabled={saveMutation.isLoading || unchanged} onClick={() => saveMutation.mutate(trimmed)}>
            Save
          </Button>
        </Gated>
      </CardContent>
    </Card>
  );
}
