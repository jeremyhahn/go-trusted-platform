'use client';

/**
 * DeviceProfileEditDialog — Edit Profile on the device profiles page (#2048).
 *
 * Edits the profile's name and model and saves them through the SDK
 * DeviceService updateProfile, PUT /api/v1/device/profiles/{id}, sending the
 * rest of the profile unchanged. Save is capability-gated on the server's
 * update route; a refusal is shown as a destructive toast.
 */

import { useEffect, useState } from 'react';
import { useDevice, type DeviceProfile } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Gated } from '@/components/features/capabilities/gated';
import { useToast } from '@/hooks/use-toast';

export const PROFILE_UPDATE_OP = 'PUT /api/v1/device/profiles/{id:[0-9]+}';

export interface DeviceProfileEditDialogProps {
  profile: DeviceProfile | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSaved?: () => void;
}

export function DeviceProfileEditDialog({ profile, open, onOpenChange, onSaved }: DeviceProfileEditDialogProps) {
  const deviceService = useDevice();
  const { toast } = useToast();
  const [name, setName] = useState(profile?.name ?? '');
  const [model, setModel] = useState(profile?.model ?? '');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    setName(profile?.name ?? '');
    setModel(profile?.model ?? '');
  }, [profile]);

  const nameValue = name.trim();
  const modelValue = model.trim();

  const fail = (message: string) => {
    toast({ title: 'Profile update failed', description: message, variant: 'destructive' });
  };

  const save = async () => {
    if (!profile) return;
    setBusy(true);
    try {
      const res = await deviceService.updateProfile({ profile: { ...profile, name: nameValue, model: modelValue } });
      if (!res.success) {
        fail(res.error?.message ?? 'profile not updated');
        return;
      }
      toast({ title: 'Profile updated', description: `${nameValue} was saved.` });
      onSaved?.();
      onOpenChange(false);
    } catch (error) {
      fail(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open && profile !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Edit Profile</DialogTitle>
          <DialogDescription>Change the profile&apos;s name and model.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="device-profile-edit-name">Name</Label>
            <Input
              id="device-profile-edit-name"
              aria-label="Profile name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="device-profile-edit-model">Model</Label>
            <Input
              id="device-profile-edit-model"
              aria-label="Profile model"
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Gated op={PROFILE_UPDATE_OP}>
            <Button onClick={save} disabled={busy || nameValue === ''}>
              Save
            </Button>
          </Gated>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
