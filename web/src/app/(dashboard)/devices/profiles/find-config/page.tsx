'use client';

/**
 * Find device config: an operator types a device's EK serial, its MAC
 * address or both, and the page shows the profile the control plane would
 * deliver to it (DeviceService.findConfigForDevice, #2049). An assigned
 * profile can be unassigned after a confirm
 * (DeviceService.unassignProfileFromDevice), and the Assign a profile card
 * binds a profile to a device (DeviceService.assignProfileToDevice); both
 * controls are gated on the server's capabilities.
 */

import { useRef, useState, type FormEvent } from 'react';
import Link from 'next/link';
import type { DeviceProfile } from 'trusted-platform-sdk';

import {
  ProfileAssignmentCard,
  ProfileUnassignButton,
} from '@/components/features/devices/profile-assignment-card';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useFindDeviceConfig } from '@/hooks/use-find-device-config';
import type { DeviceIdentity } from '@/hooks/use-find-device-config';

function sameIdentity(a: DeviceIdentity, b: DeviceIdentity | undefined): boolean {
  return b !== undefined && a.ekSerial === b.ekSerial && a.macAddress === b.macAddress;
}

export default function FindDeviceConfigPage() {
  const [ekSerial, setEkSerial] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const [result, setResult] = useState<{ identity: DeviceIdentity; profile: DeviceProfile } | null>(null);
  const lookupSeq = useRef(0);
  const find = useFindDeviceConfig();

  const blank = ekSerial.trim() === '' && macAddress.trim() === '';

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const identity = { ekSerial: ekSerial.trim(), macAddress: macAddress.trim() };
    const seq = ++lookupSeq.current;
    setResult(null);
    find.mutateAsync(identity).then(
      (profile) => {
        if (seq === lookupSeq.current) setResult(profile ? { identity, profile } : null);
      },
      () => {
        if (seq === lookupSeq.current) setResult(null);
      }
    );
  };

  // useMutation keeps `data` across requests (and clears `error` when one
  // starts), so the page shows only the latest lookup's own result, and
  // nothing while a lookup is pending (#2183 Codex).
  const shown =
    !find.isLoading && !find.error && result !== null && sameIdentity(result.identity, find.variables)
      ? result
      : null;

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

      {find.isLoading && (
        <p role="status" className="text-muted-foreground">
          Looking up the profile
        </p>
      )}

      {!find.isLoading && find.error?.status === 404 ? (
        <p className="text-muted-foreground">No profile matches this device.</p>
      ) : !find.isLoading && find.error ? (
        <div role="alert" className="text-destructive">
          Lookup refused: {find.error.message}
        </div>
      ) : null}

      {shown && (
        <Card className="max-w-lg">
          <CardHeader>
            <CardTitle>{shown.profile.name}</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-1 text-sm">
            <span>
              For EK serial {shown.identity.ekSerial || '-'}, MAC address {shown.identity.macAddress || '-'}
            </span>
            <span>Profile ID {shown.profile.id}</span>
            <span>EK serial {shown.profile.ek_serial ?? '-'}</span>
            <span>MAC address {shown.profile.mac_address ?? '-'}</span>
            <span>{shown.profile.assigned ? 'Assigned' : 'Not assigned'}</span>
            {shown.profile.assigned && (
              <ProfileUnassignButton
                profileId={shown.profile.id}
                onUnassigned={(p) => setResult({ identity: shown.identity, profile: p })}
              />
            )}
            <Link href="/devices/profiles" className="underline">
              Open profiles
            </Link>
          </CardContent>
        </Card>
      )}

      <ProfileAssignmentCard />
    </div>
  );
}
