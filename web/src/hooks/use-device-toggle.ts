'use client';

import { useDevice, useMutation } from 'trusted-platform-sdk';
import type { DeviceLifecycleResponse, UseMutationResult } from 'trusted-platform-sdk';

import { deviceToggleSuccess, type DeviceToggle } from '@/lib/device-lifecycle';
import { useToast } from './use-toast';

export interface DeviceToggleRequest {
  id: string;
  toggle: DeviceToggle;
}

/**
 * useDeviceToggle sends an operator Enable or Disable to the control
 * plane's lifecycle transition endpoints (#250) and reports the outcome:
 * the applied transition as a toast, a refusal as a destructive toast
 * carrying the server's reason. onChanged runs after a transition so the
 * caller re-reads the device and its badge follows the recorded state.
 *
 * The device table and the detail page share it, so both controls send the
 * same request and word the result the same way.
 */
export function useDeviceToggle(
  onChanged?: () => void
): UseMutationResult<DeviceLifecycleResponse, DeviceToggleRequest> {
  const deviceService = useDevice();
  const { toast } = useToast();

  return useMutation(
    async ({ id, toggle }: DeviceToggleRequest) =>
      toggle === 'enable' ? deviceService.enableDevice(id) : deviceService.disableDevice(id),
    {
      onSuccess: (result, { toggle }) => {
        toast({
          title: toggle === 'enable' ? 'Device enabled' : 'Device disabled',
          description: deviceToggleSuccess(toggle, result),
        });
        onChanged?.();
      },
      onError: (error, { toggle }) => {
        toast({
          title: toggle === 'enable' ? 'Enable refused' : 'Disable refused',
          description: error.message,
          variant: 'destructive',
        });
      },
    }
  );
}
