'use client';

/**
 * BMCBootMediaCard reads and sets a BMC profile's boot device
 * (GetBootDevice / SetBootDevice) and reads, mounts and unmounts its virtual
 * media (VirtualMediaStatus / MountISO / UnmountISO) through useBMCBootMedia,
 * which calls the SDK API client. A boot-device change takes effect at the
 * next boot. Unmount asks first in a dialog. A refusal from the control plane
 * is shown verbatim in a destructive toast.
 */

import { useCallback, useEffect, useState } from 'react';

import { Button } from '@/components/ui/button';
import { Gated } from '@/components/features/capabilities/gated';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
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
import { useToast } from '@/hooks/use-toast';
import {
  BMC_BOOT_DEVICES,
  bmcBootDeviceLabel,
  isBMCBootDevice,
  useBMCBootMedia,
  type BMCBootDevice,
  type BMCVirtualMediaStatus,
} from '@/hooks/use-bmc-boot-media';

// The server's ops for these controls (pkg/webservice/v1/bmc/routes.go).
const BMC_BOOT_DEVICE_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/boot-device';
const BMC_MOUNT_OP = 'POST /api/v1/bmc/{profileID:[0-9]+}/virtual-media';
const BMC_UNMOUNT_OP = 'DELETE /api/v1/bmc/{profileID:[0-9]+}/virtual-media';

export interface BMCBootMediaCardProps {
  profileID: string;
}

export function BMCBootMediaCard({ profileID }: BMCBootMediaCardProps) {
  const ops = useBMCBootMedia(profileID);
  const { toast } = useToast();

  const [current, setCurrent] = useState<string | null>(null);
  const [device, setDevice] = useState<BMCBootDevice>('pxe');
  const [persistent, setPersistent] = useState(false);
  const [media, setMedia] = useState<BMCVirtualMediaStatus | null>(null);
  const [isoURL, setIsoURL] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmUnmount, setConfirmUnmount] = useState(false);

  const reload = useCallback(async () => {
    const [boot, vm] = await Promise.all([ops.getBootDevice(), ops.getVirtualMedia()]);
    if (boot.success && boot.data) {
      setCurrent(boot.data.device);
      if (isBMCBootDevice(boot.data.device)) {
        setDevice(boot.data.device);
      }
    } else {
      toast({
        title: 'Boot device unavailable',
        description: boot.error?.message ?? 'The control plane did not answer',
        variant: 'destructive',
      });
    }
    if (vm.success && vm.data) {
      setMedia(vm.data);
    } else {
      toast({
        title: 'Virtual media unavailable',
        description: vm.error?.message ?? 'The control plane did not answer',
        variant: 'destructive',
      });
    }
  }, [ops, toast]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const setBootDevice = async () => {
    setBusy(true);
    try {
      const res = await ops.setBootDevice(device, persistent);
      if (res.success) {
        toast({
          title: 'Boot device set',
          description: `${bmcBootDeviceLabel(device)} at the next boot`,
          variant: 'success',
        });
        await reload();
      } else {
        toast({
          title: 'Set boot device failed',
          description: res.error?.message ?? 'The control plane refused the boot device',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const mountISO = async () => {
    setBusy(true);
    try {
      const res = await ops.mountISO(isoURL);
      if (res.success) {
        toast({
          title: 'ISO mounted',
          description: res.data?.iso_url ?? isoURL.trim(),
          variant: 'success',
        });
        setIsoURL('');
        await reload();
      } else {
        toast({
          title: 'Mount ISO failed',
          description: res.error?.message ?? 'The control plane refused the image',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const unmountISO = async () => {
    setConfirmUnmount(false);
    setBusy(true);
    try {
      const res = await ops.unmountISO();
      if (res.success) {
        toast({
          title: 'ISO unmounted',
          description: `BMC profile ${profileID}`,
          variant: 'success',
        });
        await reload();
      } else {
        toast({
          title: 'Unmount failed',
          description: res.error?.message ?? 'The control plane refused the unmount',
          variant: 'destructive',
        });
      }
    } finally {
      setBusy(false);
    }
  };

  const currentText = current ? (isBMCBootDevice(current) ? bmcBootDeviceLabel(current) : current) : 'unknown';

  return (
    <Card>
      <CardHeader>
        <CardTitle>Boot and virtual media</CardTitle>
        <CardDescription>
          The boot device takes effect at the next boot. Virtual media presents an ISO image to the host.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <section className="space-y-3">
          <p data-testid="bmc-boot-current">Current boot device: {currentText}</p>
          <div className="flex flex-wrap items-center gap-3">
            <select
              aria-label="Boot device"
              className="h-9 rounded-md border border-input bg-transparent px-3 text-sm"
              value={device}
              onChange={(e) => {
                if (isBMCBootDevice(e.target.value)) {
                  setDevice(e.target.value);
                }
              }}
            >
              {BMC_BOOT_DEVICES.map((d) => (
                <option key={d} value={d}>
                  {bmcBootDeviceLabel(d)}
                </option>
              ))}
            </select>
            <div className="flex items-center gap-2">
              <Checkbox
                id="bmc-boot-persistent"
                aria-label="Persistent"
                checked={persistent}
                onCheckedChange={(v) => setPersistent(v === true)}
              />
              <Label htmlFor="bmc-boot-persistent">Persistent</Label>
            </div>
            <Gated op={BMC_BOOT_DEVICE_OP}>
              <Button onClick={() => void setBootDevice()} disabled={busy}>
                Set boot device
              </Button>
            </Gated>
          </div>
        </section>

        <section className="space-y-3">
          <p data-testid="bmc-media-status">
            {media?.mounted ? `Mounted: ${media.image_url ?? 'an image'}` : 'No image mounted'}
          </p>
          {media?.mounted ? (
            <Gated op={BMC_UNMOUNT_OP}>
              <Button variant="destructive" onClick={() => setConfirmUnmount(true)} disabled={busy}>
                Unmount
              </Button>
            </Gated>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <Input
                aria-label="ISO URL"
                className="max-w-md"
                placeholder="https://images.example/os.iso"
                value={isoURL}
                onChange={(e) => setIsoURL(e.target.value)}
              />
              <Gated op={BMC_MOUNT_OP}>
                <Button onClick={() => void mountISO()} disabled={busy || isoURL.trim() === ''}>
                  Mount ISO
                </Button>
              </Gated>
            </div>
          )}
        </section>
      </CardContent>

      <Dialog open={confirmUnmount} onOpenChange={setConfirmUnmount}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Unmount the virtual media?</DialogTitle>
            <DialogDescription>The host loses the mounted image on BMC profile {profileID}.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmUnmount(false)} disabled={busy}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void unmountISO()} disabled={busy}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
