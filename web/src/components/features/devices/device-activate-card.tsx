'use client';

/**
 * DeviceActivateCard — check a device's activation from its detail page (#2048).
 *
 * "Check activation" calls the SDK DeviceService activateDevice, POST
 * /api/v1/device/activate-json, with the serial and an optional MAC address
 * (sent as serial and mac_address). That route is a lookup: it matches the
 * device to a profile and reports the VLAN the profile admits. It changes
 * nothing on the server and moves no port; a device activates itself over
 * mTLS (POST /device/activate). The card shows the profile match and the
 * admitted VLAN, never that the device was activated. The control sits behind
 * the capability gate. A refusal (no serial, no device, no matching profile)
 * is a destructive toast.
 */

import { useEffect, useState } from 'react';
import { useDevice, useMutation } from 'trusted-platform-sdk';
import type { ActivateDeviceResponse } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Gated } from '@/components/features/capabilities/gated';
import { useToast } from '@/hooks/use-toast';

export const DEVICE_ACTIVATE_OP = 'POST /api/v1/device/activate-json';

export interface DeviceActivateCardProps {
  serial?: string | undefined;
  /** Called after a successful check; the page re-reads the device. */
  onChecked: () => void;
}

interface ActivateVars {
  serial: string;
  macAddress: string;
}

export function DeviceActivateCard({ serial, onChecked }: DeviceActivateCardProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [serialValue, setSerialValue] = useState(serial ?? '');
  const [mac, setMac] = useState('');
  const [result, setResult] = useState<ActivateDeviceResponse | undefined>(undefined);

  useEffect(() => {
    setSerialValue(serial ?? '');
  }, [serial]);

  const activateMutation = useMutation(
    ({ serial: s, macAddress }: ActivateVars) =>
      deviceService.activateDevice(macAddress ? { serial: s, macAddress } : { serial: s }),
    {
      onSuccess: (answer: ActivateDeviceResponse) => {
        setResult(answer);
        toast({
          title: 'Activation check',
          description:
            answer.vlan !== undefined
              ? `Admitted VLAN ${answer.vlan}. The device activates itself over mTLS.`
              : 'Profile matched. The device activates itself over mTLS.',
        });
        onChecked();
      },
      onError: (error) => {
        setResult(undefined);
        toast({ title: 'Activation check failed', description: error.message, variant: 'destructive' });
      },
    }
  );

  const trimmedSerial = serialValue.trim();
  const trimmedMac = mac.trim();

  return (
    <Card data-testid="device-activate-card">
      <CardHeader>
        <CardTitle>Activation check</CardTitle>
        <CardDescription>
          Look up the profile and VLAN this device would be admitted to. This does not activate the device or move its
          port.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="device-activate-serial">Serial</Label>
            <Input id="device-activate-serial" value={serialValue} onChange={(e) => setSerialValue(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="device-activate-mac">MAC address</Label>
            <Input
              id="device-activate-mac"
              placeholder="02:00:00:00:00:01"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
            />
          </div>
        </div>
        <Gated op={DEVICE_ACTIVATE_OP}>
          <Button
            data-testid="device-activate-submit"
            disabled={activateMutation.isLoading || trimmedSerial === ''}
            onClick={() => activateMutation.mutate({ serial: trimmedSerial, macAddress: trimmedMac })}
          >
            Check activation
          </Button>
        </Gated>
        {result && (
          <p data-testid="device-activate-result" className="text-sm text-muted-foreground">
            Profile matched
            {result.vlan !== undefined && <> · admitted VLAN {result.vlan}</>}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
