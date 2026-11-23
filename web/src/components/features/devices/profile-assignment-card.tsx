'use client';

/**
 * Device profile assignment (#2049, epic #1665): a card that binds a device
 * profile to a device (DeviceService.assignProfileToDevice) and a button
 * that unbinds it after a confirm (DeviceService.unassignProfileFromDevice),
 * each behind the server's capability for its operation.
 */

import { useState, type FormEvent } from 'react';
import type { DeviceProfile } from 'trusted-platform-sdk';

import { Gated } from '@/components/features/capabilities/gated';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { useProfileAssignment } from '@/hooks/use-profile-assignment';
import { useToast } from '@/hooks/use-toast';

export const ASSIGN_PROFILE_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/assign';
export const UNASSIGN_PROFILE_OP = 'POST /api/v1/device/profiles/{id:[0-9]+}/unassign';

export function ProfileAssignmentCard({ onAssigned }: { onAssigned?: (profile: DeviceProfile) => void }) {
  const { assign } = useProfileAssignment();
  const { toast } = useToast();
  const [profileId, setProfileId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [ekSerial, setEkSerial] = useState('');
  const [macAddress, setMacAddress] = useState('');
  const [ekCert, setEkCert] = useState('');
  const [assigned, setAssigned] = useState<DeviceProfile | null>(null);

  const noIdentity = deviceId.trim() === '' && ekSerial.trim() === '' && macAddress.trim() === '';
  const disabled = assign.isLoading || profileId.trim() === '' || noIdentity;

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (disabled) return;
    setAssigned(null);
    assign.mutateAsync({ profileId, deviceId, ekSerial, macAddress, ekCert }).then(
      (profile) => {
        setAssigned(profile);
        toast({ title: 'Profile assigned', description: `Profile ${profile.name} assigned`, variant: 'success' });
        onAssigned?.(profile);
      },
      () => {
        // The refusal is shown from assign.error below.
      }
    );
  };

  return (
    <Card className="max-w-lg">
      <CardHeader>
        <CardTitle>Assign a profile</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="grid gap-4">
          <div className="grid gap-2">
            <Label htmlFor="assign-profile-id">Profile ID</Label>
            <Input
              id="assign-profile-id"
              inputMode="numeric"
              value={profileId}
              onChange={(e) => setProfileId(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="assign-device-id">Device ID</Label>
            <Input id="assign-device-id" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="assign-ek-serial">EK serial</Label>
            <Input id="assign-ek-serial" value={ekSerial} onChange={(e) => setEkSerial(e.target.value)} />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="assign-mac-address">MAC address</Label>
            <Input
              id="assign-mac-address"
              placeholder="aa:bb:cc:dd:ee:ff"
              value={macAddress}
              onChange={(e) => setMacAddress(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="assign-ek-cert">EK certificate (PEM)</Label>
            <Textarea id="assign-ek-cert" rows={4} value={ekCert} onChange={(e) => setEkCert(e.target.value)} />
          </div>
          <div>
            <Gated op={ASSIGN_PROFILE_OP}>
              <Button type="submit" disabled={disabled}>
                Assign profile
              </Button>
            </Gated>
          </div>
          {!assign.isLoading && assign.error ? (
            <div role="alert" className="text-sm text-destructive">
              Assignment refused: {assign.error.message}
            </div>
          ) : null}
          {!assign.isLoading && !assign.error && assigned ? (
            <p className="text-sm">Profile {assigned.name} assigned</p>
          ) : null}
        </form>
      </CardContent>
    </Card>
  );
}

export function ProfileUnassignButton({
  profileId,
  onUnassigned,
}: {
  profileId: string;
  onUnassigned: (profile: DeviceProfile) => void;
}) {
  const { unassign } = useProfileAssignment();
  const { toast } = useToast();
  const [open, setOpen] = useState(false);

  const confirm = () => {
    unassign.mutateAsync(profileId).then(
      (profile) => {
        setOpen(false);
        toast({ title: 'Profile unassigned', description: `Profile ${profile.name} unassigned`, variant: 'success' });
        onUnassigned(profile);
      },
      (err: unknown) => {
        setOpen(false);
        toast({
          title: 'Unassign refused',
          description: err instanceof Error ? err.message : String(err),
          variant: 'destructive',
        });
      }
    );
  };

  return (
    <>
      <div>
        <Gated op={UNASSIGN_PROFILE_OP}>
          <Button type="button" variant="outline" size="sm" disabled={unassign.isLoading} onClick={() => setOpen(true)}>
            Unassign
          </Button>
        </Gated>
      </div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unassign profile?</DialogTitle>
            <DialogDescription>
              This clears the profile&apos;s EK serial, MAC address and prestaged EK certificate, so no
              device is delivered it until it is assigned again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="button" variant="destructive" disabled={unassign.isLoading} onClick={confirm}>
              Unassign
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
