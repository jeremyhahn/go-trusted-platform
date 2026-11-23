'use client';

/**
 * DeviceSerialLookup — the device count and a find-by-serial lookup on the
 * devices list (#2048).
 *
 * The count reads the SDK DeviceService countDevices, GET /api/v1/devices/count,
 * once the server offers it. "Find" calls findDeviceBySerial,
 * GET /api/v1/devices/serial/{serial}, and opens the device page; a refusal
 * is shown as a destructive toast. Each control is capability-gated.
 */

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useDevice } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Gated } from '@/components/features/capabilities/gated';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';

export const DEVICE_COUNT_OP = 'GET /api/v1/devices/count';
export const DEVICE_FIND_BY_SERIAL_OP = 'GET /api/v1/devices/serial/{serial}';

export function DeviceSerialLookup() {
  const deviceService = useDevice();
  const router = useRouter();
  const { toast } = useToast();
  const { capability } = useCapabilities();
  const countEnabled = capability(DEVICE_COUNT_OP).enabled;

  const [count, setCount] = useState<number | undefined>(undefined);
  const [serial, setSerial] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!countEnabled) return;
    let live = true;
    deviceService
      .countDevices()
      .then((res) => {
        if (live && res.success && res.data) setCount(res.data.count);
      })
      .catch(() => {
        // The count is informational; a failed read leaves it hidden.
      });
    return () => {
      live = false;
    };
  }, [countEnabled, deviceService]);

  const trimmed = serial.trim();

  const lookUp = async () => {
    setBusy(true);
    try {
      const res = await deviceService.findDeviceBySerial(trimmed);
      if (res.success && res.data) {
        router.push(`/devices/${res.data.id}`);
        return;
      }
      toast({
        title: 'Device lookup failed',
        description: res.error?.message ?? 'device not found',
        variant: 'destructive',
      });
    } catch (error) {
      toast({
        title: 'Device lookup failed',
        description: error instanceof Error ? error.message : String(error),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-2" data-testid="device-serial-lookup">
      {countEnabled && count !== undefined && <span data-testid="device-count">{count} devices</span>}
      <Input
        aria-label="Find by serial"
        placeholder="Serial number"
        value={serial}
        onChange={(e) => setSerial(e.target.value)}
        className="w-48"
      />
      <Gated op={DEVICE_FIND_BY_SERIAL_OP}>
        <Button variant="outline" disabled={busy || trimmed === ''} onClick={lookUp}>
          Find
        </Button>
      </Gated>
    </div>
  );
}
