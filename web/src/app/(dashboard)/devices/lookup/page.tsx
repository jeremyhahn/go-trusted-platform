"use client";

/**
 * Device lookup (#1743): device and profile counts, lookups by serial, MAC
 * and match criteria, the device's own profile, partial updates, activation
 * and attestation. Every write waits for a confirm dialog.
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
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { useDeviceLookup } from '@/hooks';
import type { Device, DeviceProfile } from 'trusted-platform-sdk';

interface PendingAction {
  title: string;
  description: string;
  run: () => Promise<unknown>;
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <div className="grid gap-1">
      <Label htmlFor={id}>{label}</Label>
      <Input id={id} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} />
    </div>
  );
}

function DeviceSummary({ device }: { device: Device }) {
  return (
    <dl className="grid grid-cols-2 gap-1 text-sm" data-testid="device-result">
      <dt className="text-muted-foreground">ID</dt>
      <dd>{device.id}</dd>
      <dt className="text-muted-foreground">Serial</dt>
      <dd>{device.serial}</dd>
      <dt className="text-muted-foreground">Model</dt>
      <dd>{device.model || '—'}</dd>
    </dl>
  );
}

function ProfileSummary({ profile }: { profile: DeviceProfile }) {
  return (
    <dl className="grid grid-cols-2 gap-1 text-sm" data-testid="profile-result">
      <dt className="text-muted-foreground">ID</dt>
      <dd>{profile.id}</dd>
      <dt className="text-muted-foreground">Name</dt>
      <dd>{profile.name}</dd>
      <dt className="text-muted-foreground">Model</dt>
      <dd>{profile.model || '—'}</dd>
    </dl>
  );
}

export default function DeviceLookupPage() {
  const lookup = useDeviceLookup();
  const [pending, setPending] = useState<PendingAction | null>(null);

  const [deviceSerial, setDeviceSerial] = useState('');
  const [device, setDevice] = useState<Device | null>(null);
  const [deviceModel, setDeviceModel] = useState('');
  const [evidence, setEvidence] = useState('');

  const [activateSerial, setActivateSerial] = useState('');
  const [activateMAC, setActivateMAC] = useState('');

  const [profileMAC, setProfileMAC] = useState('');
  const [profileSerial, setProfileSerial] = useState('');
  const [matchModel, setMatchModel] = useState('');
  const [profile, setProfile] = useState<DeviceProfile | null>(null);
  const [profileName, setProfileName] = useState('');
  const [profileMissing, setProfileMissing] = useState(false);

  const showDevice = (found: Device | undefined) => {
    setDevice(found ?? null);
    setDeviceModel(found?.model ?? '');
  };
  const showProfile = (found: DeviceProfile | undefined) => {
    setProfile(found ?? null);
    setProfileName(found?.name ?? '');
    setProfileMissing(!found);
  };

  const confirmPending = async () => {
    const action = pending;
    setPending(null);
    if (!action) return;
    try {
      await action.run();
    } catch {
      // The hook's onError raised the toast.
    }
  };

  const findDevice = async () => {
    try {
      const result = await lookup.findDeviceBySerial.mutateAsync(deviceSerial.trim());
      showDevice(result);
    } catch {
      showDevice(undefined);
    }
  };

  const runProfileLookup = async (lookupFn: () => Promise<DeviceProfile>) => {
    try {
      showProfile(await lookupFn());
    } catch {
      showProfile(undefined);
    }
  };

  const deviceProfile = lookup.getDeviceProfile.data;
  const attestResult = lookup.attestDevice.data;
  const activation = lookup.activateDevice.data;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Device Lookup</h1>
        <p className="text-muted-foreground">
          Find devices and profiles, update them, activate and attest devices
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Devices</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="device-count">
              {lookup.deviceCount.data?.count ?? '—'}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Profiles</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold" data-testid="profile-count">
              {lookup.profileCount.data?.count ?? '—'}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Device by serial</CardTitle>
          <CardDescription>Find a device, edit it, or attest it with TPM evidence</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-end gap-2">
            <Field id="device-serial" label="Device serial" value={deviceSerial} onChange={setDeviceSerial} />
            <Button onClick={findDevice} disabled={!deviceSerial.trim() || lookup.findDeviceBySerial.isLoading}>
              Find device
            </Button>
          </div>
          {lookup.findDeviceBySerial.isSettled && !device && (
            <p className="text-sm text-muted-foreground">No device found</p>
          )}
          {device && (
            <>
              <DeviceSummary device={device} />
              <div className="flex items-end gap-2">
                <Field id="device-model" label="Model" value={deviceModel} onChange={setDeviceModel} />
                <Button
                  onClick={() =>
                    setPending({
                      title: 'Update device',
                      description: `Save the model of device ${device.id}?`,
                      run: async () => {
                        const result = await lookup.updateDevice.mutateAsync({ id: device.id, model: deviceModel });
                        showDevice(result);
                      },
                    })
                  }
                >
                  Update device
                </Button>
              </div>
              <div className="grid gap-1">
                <Label htmlFor="attest-evidence">Attestation evidence (base64)</Label>
                <Textarea id="attest-evidence" value={evidence} onChange={(e) => setEvidence(e.target.value)} />
              </div>
              <div>
                <Button
                  variant="outline"
                  disabled={!evidence.trim()}
                  onClick={() =>
                    setPending({
                      title: 'Attest device',
                      description: `Verify the evidence for device ${device.id}? Its attestation status changes with the verdict.`,
                      run: () => lookup.attestDevice.mutateAsync({ id: device.id, request: { evidence: evidence.trim() } }),
                    })
                  }
                >
                  Attest device
                </Button>
              </div>
              {attestResult && (
                <p className="text-sm" data-testid="attest-result">
                  {attestResult.verified ? 'Verified' : 'Not verified'}: {attestResult.attestation_status}
                  {attestResult.message ? ` (${attestResult.message})` : ''}
                </p>
              )}
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Activate device</CardTitle>
          <CardDescription>Move an enrolled device onto its admitted network</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-2 md:grid-cols-2">
            <Field id="activate-serial" label="Serial" value={activateSerial} onChange={setActivateSerial} />
            <Field id="activate-mac" label="MAC address" value={activateMAC} onChange={setActivateMAC} />
          </div>
          <div>
            <Button
              variant="destructive"
              disabled={!activateSerial.trim() || !activateMAC.trim()}
              onClick={() =>
                setPending({
                  title: 'Activate device',
                  description: `Activate device ${activateSerial.trim()}? Its switch port moves to the admitted network.`,
                  run: () =>
                    lookup.activateDevice.mutateAsync({
                      serial: activateSerial.trim(),
                      macAddress: activateMAC.trim(),
                    }),
                })
              }
            >
              Activate device
            </Button>
          </div>
          {activation && (
            <p className="text-sm" data-testid="activate-result">
              {activation.status}
              {activation.vlan !== undefined ? ` (VLAN ${activation.vlan})` : ''}
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Device profile</CardTitle>
          <CardDescription>The profile the calling device resolves to from its client certificate</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div>
            <Button variant="outline" onClick={() => lookup.getDeviceProfile.mutate()}>
              Load device profile
            </Button>
          </div>
          {deviceProfile && (
            <dl className="grid grid-cols-2 gap-1 text-sm" data-testid="device-profile-result">
              <dt className="text-muted-foreground">Serial</dt>
              <dd>{deviceProfile.serialNumber}</dd>
              <dt className="text-muted-foreground">Admitted network</dt>
              <dd>{JSON.stringify(deviceProfile.admittedNetwork)}</dd>
            </dl>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Profile lookup</CardTitle>
          <CardDescription>Find a profile by MAC address, serial, or match criteria, then edit it</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-end gap-2">
            <Field id="profile-mac" label="Profile MAC address" value={profileMAC} onChange={setProfileMAC} />
            <Button
              disabled={!profileMAC.trim()}
              onClick={() => runProfileLookup(() => lookup.findProfileByMAC.mutateAsync(profileMAC.trim()))}
            >
              Find by MAC
            </Button>
          </div>
          <div className="flex items-end gap-2">
            <Field id="profile-serial" label="Profile serial" value={profileSerial} onChange={setProfileSerial} />
            <Button
              disabled={!profileSerial.trim()}
              onClick={() => runProfileLookup(() => lookup.findProfileBySerial.mutateAsync(profileSerial.trim()))}
            >
              Find by serial
            </Button>
          </div>
          <div className="flex items-end gap-2">
            <Field id="match-model" label="Match model" value={matchModel} onChange={setMatchModel} />
            <Button
              disabled={!profileMAC.trim() && !profileSerial.trim() && !matchModel.trim()}
              onClick={() =>
                runProfileLookup(() =>
                  lookup.findMatchingProfile.mutateAsync({
                    macAddress: profileMAC.trim() || undefined,
                    serial: profileSerial.trim() || undefined,
                    model: matchModel.trim() || undefined,
                  })
                )
              }
            >
              Match profile
            </Button>
          </div>
          {profileMissing && <p className="text-sm text-muted-foreground">No profile found</p>}
          {profile && (
            <>
              <ProfileSummary profile={profile} />
              <div className="flex items-end gap-2">
                <Field id="profile-name" label="Profile name" value={profileName} onChange={setProfileName} />
                <Button
                  disabled={!profileName.trim()}
                  onClick={() =>
                    setPending({
                      title: 'Update profile',
                      description: `Save the name of profile ${profile.id}?`,
                      run: async () => {
                        const result = await lookup.updateProfile.mutateAsync({
                          // The server replaces the whole profile: send every field it holds.
                          ...profile,
                          name: profileName.trim(),
                        });
                        showProfile(result);
                      },
                    })
                  }
                >
                  Update profile
                </Button>
              </div>
            </>
          )}
        </CardContent>
      </Card>

      <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{pending?.title}</DialogTitle>
            <DialogDescription>{pending?.description}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button onClick={confirmPending}>Confirm</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
