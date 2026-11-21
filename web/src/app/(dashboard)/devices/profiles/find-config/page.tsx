'use client';

/**
 * Find device config: an operator types a device's EK serial, its MAC
 * address or both, and the page shows the profile the control plane would
 * deliver to it (DeviceService.findConfigForDevice, #2049).
 */

import { useState, type FormEvent } from 'react';
import Link from 'next/link';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useFindDeviceConfig } from '@/hooks/use-find-device-config';

export default function FindDeviceConfigPage() {
  const [ekSerial, setEkSerial] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const find = useFindDeviceConfig();

  const blank = ekSerial.trim() === '' && macAddress.trim() === '';

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    find.mutate({ ekSerial, macAddress });
  };

  const profile = find.data;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Find device config</h1>
        <p className="text-muted-foreground">
          Look up the profile a device is delivered, by its EK serial, its MAC address or both.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="grid max-w-lg gap-4">
        <div className="grid gap-2">
          <Label htmlFor="ek-serial">EK serial</Label>
          <Input id="ek-serial" value={ekSerial} onChange={(e) => setEkSerial(e.target.value)} />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="mac-address">MAC address</Label>
          <Input
            id="mac-address"
            placeholder="aa:bb:cc:dd:ee:ff"
            value={macAddress}
            onChange={(e) => setMacAddress(e.target.value)}
          />
        </div>
        <div>
          <Button type="submit" disabled={find.isLoading || blank}>
            Find config
          </Button>
        </div>
      </form>

      {find.error?.status === 404 ? (
        <p className="text-muted-foreground">No profile matches this device.</p>
      ) : find.error ? (
        <div role="alert" className="text-destructive">
          Lookup refused: {find.error.message}
        </div>
      ) : null}

      {!find.error && profile && (
        <Card className="max-w-lg">
          <CardHeader>
            <CardTitle>{profile.name}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1 text-sm">
            <span>Profile ID {profile.id}</span>
            <span>EK serial {profile.ek_serial ?? '-'}</span>
            <span>MAC address {profile.mac_address ?? '-'}</span>
            <span>{profile.assigned ? 'Assigned' : 'Not assigned'}</span>
            <Link href="/devices/profiles" className="underline">
              Open profiles
            </Link>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
