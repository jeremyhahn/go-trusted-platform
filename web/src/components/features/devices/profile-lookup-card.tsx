'use client';

/**
 * ProfileLookupCard finds a device profile by MAC address or by serial number
 * (FindProfileByMACAddress, FindProfileBySerial) and shows what the control
 * plane answered, or its refusal verbatim. It is read-only and gates nothing.
 */

import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { useDeviceProfileLookup, type LookedUpProfile } from '@/hooks/use-device-profile-lookup';

interface LookupResult {
  success: boolean;
  data?: LookedUpProfile;
  error?: { message?: string };
}

function show(value: string | number | undefined): string {
  return value === undefined || value === null || value === '' ? '-' : String(value);
}

export function ProfileLookupCard(): JSX.Element {
  const lookup = useDeviceProfileLookup();
  const { toast } = useToast();
  const [mac, setMac] = useState('');
  const [serial, setSerial] = useState('');
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<LookedUpProfile | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);

  const run = async (call: () => Promise<LookupResult>) => {
    setBusy(true);
    setRefusal(null);
    try {
      const res = await call();
      if (res.success && res.data) {
        setProfile(res.data);
      } else {
        setProfile(null);
        setRefusal(res.error?.message || 'The control plane found no profile');
      }
    } catch (err) {
      setProfile(null);
      setRefusal(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const required = (title: string, description: string) =>
    toast({ title, description, variant: 'destructive' });

  const findByMAC = () => {
    const value = mac.trim();
    if (!value) {
      required('MAC address required', 'enter a value to look up');
      return;
    }
    void run(() => lookup.byMAC(value));
  };

  const findBySerial = () => {
    const value = serial.trim();
    if (!value) {
      required('Serial number required', 'enter a value to look up');
      return;
    }
    void run(() => lookup.bySerial(value));
  };

  return (
    <Card data-testid="profile-lookup-card">
      <CardHeader>
        <CardTitle>Find a device profile</CardTitle>
        <CardDescription>Look a profile up by MAC address or serial number.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex gap-2">
          <Input aria-label="MAC address" value={mac} onChange={(e) => setMac(e.target.value)} />
          <Button onClick={findByMAC} disabled={busy}>
            Find by MAC
          </Button>
        </div>
        <div className="flex gap-2">
          <Input aria-label="Serial number" value={serial} onChange={(e) => setSerial(e.target.value)} />
          <Button onClick={findBySerial} disabled={busy}>
            Find by serial
          </Button>
        </div>

        {refusal !== null && (
          <p role="alert" className="text-sm text-destructive whitespace-pre-wrap break-words">
            {refusal}
          </p>
        )}

        {profile && (
          <dl data-testid="profile-lookup-result" className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt className="text-muted-foreground">Name</dt>
            <dd>{show(profile.name)}</dd>
            <dt className="text-muted-foreground">ID</dt>
            <dd>{show(profile.id)}</dd>
            <dt className="text-muted-foreground">Model</dt>
            <dd>{show(profile.model)}</dd>
            <dt className="text-muted-foreground">Role</dt>
            <dd>{show(profile.role)}</dd>
            <dt className="text-muted-foreground">MAC</dt>
            <dd className="font-mono">{show(profile.mac_address)}</dd>
            <dt className="text-muted-foreground">EK serial</dt>
            <dd className="font-mono">{show(profile.ek_serial)}</dd>
            <dt className="text-muted-foreground">Networks</dt>
            <dd>
              {show(profile.enrollment_network)} → {show(profile.post_enrollment_network)}
            </dd>
            <dt className="text-muted-foreground">Status</dt>
            <dd>
              <Badge data-testid="profile-lookup-assigned" variant={profile.assigned ? 'default' : 'secondary'}>
                {profile.assigned ? 'Assigned' : 'Unassigned'}
              </Badge>
            </dd>
          </dl>
        )}
      </CardContent>
    </Card>
  );
}
