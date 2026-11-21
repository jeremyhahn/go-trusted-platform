'use client';

import * as React from 'react';
import { usePXE } from 'trusted-platform-sdk';
import type { PXEDeviceInfo } from 'trusted-platform-sdk';
import { useToast } from './use-toast';

/**
 * Device actions on the PXE page (#2062): authorize, quarantine, retry and
 * remove a device through client.pxe. The server decides which state
 * transitions are allowed; the hook only reports the outcome.
 */
export interface UsePXEDeviceActionsResult {
  authorize(device: PXEDeviceInfo, targetVlan: number): Promise<boolean>;
  quarantine(device: PXEDeviceInfo, reason: string): Promise<boolean>;
  retry(device: PXEDeviceInfo): Promise<boolean>;
  remove(device: PXEDeviceInfo): Promise<boolean>;
  /** The id of the device whose action is in flight, or null. */
  pendingId: string | null;
}

export function usePXEDeviceActions(onChanged?: () => void): UsePXEDeviceActionsResult {
  const pxe = usePXE();
  const { toast } = useToast();
  const [pendingId, setPendingId] = React.useState<string | null>(null);

  const run = React.useCallback(
    async (
      device: PXEDeviceInfo,
      call: () => Promise<{ error?: { message?: string } } | undefined | void>,
      ok: string,
      fail: string,
    ): Promise<boolean> => {
      setPendingId(device.id);
      try {
        const res = await call();
        if (res && res.error) {
          throw new Error(res.error.message || fail);
        }
        toast({ title: ok, description: device.macAddress, variant: 'success' });
        onChanged?.();
        return true;
      } catch (err) {
        toast({
          title: fail,
          description: err instanceof Error ? err.message : 'Unknown error',
          variant: 'destructive',
        });
        return false;
      } finally {
        setPendingId(null);
      }
    },
    [toast, onChanged],
  );

  const authorize = React.useCallback(
    (device: PXEDeviceInfo, targetVlan: number) =>
      run(
        device,
        () => pxe.authorizeDevice({ deviceId: device.id, targetVlan }),
        'Device authorized',
        'Failed to authorize device',
      ),
    [pxe, run],
  );

  const quarantine = React.useCallback(
    (device: PXEDeviceInfo, reason: string) =>
      run(
        device,
        () => pxe.quarantineDevice({ deviceId: device.id, reason }),
        'Device quarantined',
        'Failed to quarantine device',
      ),
    [pxe, run],
  );

  const retry = React.useCallback(
    (device: PXEDeviceInfo) =>
      run(device, () => pxe.retryDevice(device.id), 'Device retry started', 'Failed to retry device'),
    [pxe, run],
  );

  const remove = React.useCallback(
    (device: PXEDeviceInfo) =>
      run(device, () => pxe.removeDevice(device.id), 'Device removed', 'Failed to remove device'),
    [pxe, run],
  );

  return { authorize, quarantine, retry, remove, pendingId };
}
