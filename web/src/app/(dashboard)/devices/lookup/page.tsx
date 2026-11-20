"use client";

/**
 * Device lookup (#1743): device and profile counts, lookups by serial, MAC
 * and match criteria, profiles by ID, partial updates and activation. Every
 * write waits for a confirm dialog. Pasted-evidence attestation is not
 * offered: it is replayable until a server-issued challenge exists (#2134).
 * The device-facing routes (/device/profile, /device/boot,
 * /device/boot/certificate) have no control: they are served only to the
 * device over its own mTLS connection (ruling 1042).
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
import { useDeviceLookup } from '@/hooks';
import { DeviceRouteGate } from './device-route-gate';
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

  const [activateSerial, setActivateSerial] = useState('');
  const [activateMAC, setActivateMAC] = useState('');
  // The target the shown activation result belongs to. The mutation keeps
  // its data across a later failed or pending request, so a result shows
  // only while this matches the inputs.
  const [activatedFor, setActivatedFor] = useState<string | null>(null);

  const [profileID, setProfileID] = useState('');
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

  const activateTarget = `${activateSerial.trim()}|${activateMAC.trim()}`;
  const changeActivateTarget = (set: (value: string) => void) => (value: string) => {
    set(value);
    setActivatedFor(null);
    lookup.activateDevice.reset();
  };
  const activation =
    lookup.activateDevice.isSuccess && activatedFor === activateTarget ? lookup.activateDevice.data : undefined;

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Device Lookup</h1>
        <p className="text-muted-foreground">
          Find devices and profiles, update them, and look up device activation
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
          {/* Attestation is gated off (DeviceRouteGate): the server verifies
              pasted evidence against the nonce it carries, with no age limit,
              so an old quote would replay as a fresh verdict. A server-issued
              challenge is #2134. */}
          <CardDescription>Find a device and edit it</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-end gap-2">
            <Field id="device-serial" label="Device serial" value={deviceSerial} onChange={setDeviceSerial} />
            <Button onClick={findDevice} disabled={!deviceSerial.trim() || lookup.findDeviceBySerial.isLoading}>
              Find device
            </Button>
          </div>
          <DeviceRouteGate operation="AttestDevice" variant="outline">
            Verify attestation
          </DeviceRouteGate>
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
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Activate device</CardTitle>
          <CardDescription>
            Look up the admitted network VLAN an enrolled device&apos;s profile assigns. This does not program the
            switch or change the device&apos;s state.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid gap-2 md:grid-cols-2">
            <Field
              id="activate-serial"
              label="Serial"
              value={activateSerial}
              onChange={changeActivateTarget(setActivateSerial)}
            />
            <Field
              id="activate-mac"
              label="MAC address"
              value={activateMAC}
              onChange={changeActivateTarget(setActivateMAC)}
            />
          </div>
          <div>
            <Button
              variant="destructive"
              disabled={!activateSerial.trim() || !activateMAC.trim()}
              onClick={() => {
                const target = activateTarget;
                setPending({
                  title: 'Activate device',
                  description: `Look up the admitted VLAN for device ${activateSerial.trim()}? This does not program the switch: the device stays on its current network.`,
                  run: async () => {
                    setActivatedFor(null);
                    lookup.activateDevice.reset();
                    await lookup.activateDevice.mutateAsync({
                      serial: activateSerial.trim(),
                      macAddress: activateMAC.trim(),
                    });
                    setActivatedFor(target);
                  },
                });
              }}
            >
              Activate device
            </Button>
          </div>
          {activation && (
            <p className="text-sm" data-testid="activate-result">
              {activation.vlan !== undefined ? `Admitted VLAN ${activation.vlan}` : 'No admitted VLAN'} (status{' '}
              {activation.status}; switch not changed)
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Profile lookup</CardTitle>
          <CardDescription>Find a profile by ID, MAC address, serial, or match criteria, then edit it</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex items-end gap-2">
            <Field id="profile-id" label="Profile ID" value={profileID} onChange={setProfileID} />
            <Button
              disabled={!/^\d+$/.test(profileID.trim())}
              onClick={() => runProfileLookup(() => lookup.getProfile.mutateAsync(profileID.trim()))}
            >
              Find by ID
            </Button>
          </div>
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
                          // Fields the REST wire cannot carry (tenant, BMC, workload PCR)
                          // are kept from the stored profile by ProfileService.Update.
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
