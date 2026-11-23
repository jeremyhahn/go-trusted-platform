'use client';

/**
 * DeviceProfileLookup — the profile count and the profile lookups on the
 * device profiles page (#2048).
 *
 * The count reads the SDK DeviceService countProfiles,
 * GET /api/v1/device/profiles/count, once the server offers it. "Find by MAC"
 * calls findProfileByMACAddress, "Find by serial" calls findProfileBySerial
 * and "Match" calls findMatchingProfile with the non-empty MAC, serial and
 * model. The found profile is shown in place; a refusal is shown as a
 * destructive toast. Each control is capability-gated.
 */

import { useEffect, useState } from 'react';
import { useDevice } from 'trusted-platform-sdk';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Gated } from '@/components/features/capabilities/gated';
import { useCapabilities } from '@/hooks/use-capabilities';
import { useToast } from '@/hooks/use-toast';

export const PROFILE_COUNT_OP = 'GET /api/v1/device/profiles/count';
export const PROFILE_FIND_BY_MAC_OP = 'GET /api/v1/device/profiles/mac/{mac}';
export const PROFILE_FIND_BY_SERIAL_OP = 'GET /api/v1/device/profiles/serial/{serial}';
export const PROFILE_MATCH_OP = 'POST /api/v1/device/profiles/match';

interface FoundProfile {
  id: string | number;
  name: string;
  role?: string;
}

interface LookupAnswer {
  success: boolean;
  data?: FoundProfile;
  error?: { message?: string };
}

export function DeviceProfileLookup() {
  const deviceService = useDevice();
  const { toast } = useToast();
  const { capability } = useCapabilities();
  const countEnabled = capability(PROFILE_COUNT_OP).enabled;

  const [count, setCount] = useState<number | undefined>(undefined);
  const [mac, setMac] = useState('');
  const [serial, setSerial] = useState('');
  const [model, setModel] = useState('');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<FoundProfile | undefined>(undefined);

  useEffect(() => {
    if (!countEnabled) return;
    let live = true;
    deviceService
      .countProfiles()
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

  const macValue = mac.trim();
  const serialValue = serial.trim();
  const modelValue = model.trim();

  const fail = (message: string) => {
    setResult(undefined);
    toast({ title: 'Profile lookup failed', description: message, variant: 'destructive' });
  };

  const lookUp = async (call: () => Promise<LookupAnswer>) => {
    setBusy(true);
    try {
      const res = await call();
      if (res.success && res.data) {
        setResult(res.data);
        return;
      }
      fail(res.error?.message ?? 'profile not found');
    } catch (error) {
      fail(error instanceof Error ? error.message : String(error));
    } finally {
      setBusy(false);
    }
  };

  const findByMAC = () => lookUp(() => deviceService.findProfileByMACAddress(macValue));
  const findBySerial = () => lookUp(() => deviceService.findProfileBySerial(serialValue));
  const match = () =>
    lookUp(() =>
      deviceService.findMatchingProfile({
        ...(macValue && { macAddress: macValue }),
        ...(serialValue && { serial: serialValue }),
        ...(modelValue && { model: modelValue }),
      })
    );

  return (
    <div className="flex flex-wrap items-center gap-2" data-testid="device-profile-lookup">
      {countEnabled && count !== undefined && <span data-testid="device-profile-count">{count} profiles</span>}
      <Input
        aria-label="Profile MAC address"
        placeholder="MAC address"
        value={mac}
        onChange={(e) => setMac(e.target.value)}
        className="w-40"
      />
      <Gated op={PROFILE_FIND_BY_MAC_OP}>
        <Button variant="outline" disabled={busy || macValue === ''} onClick={findByMAC}>
          Find by MAC
        </Button>
      </Gated>
      <Input
        aria-label="Profile serial"
        placeholder="Serial number"
        value={serial}
        onChange={(e) => setSerial(e.target.value)}
        className="w-36"
      />
      <Gated op={PROFILE_FIND_BY_SERIAL_OP}>
        <Button variant="outline" disabled={busy || serialValue === ''} onClick={findBySerial}>
          Find by serial
        </Button>
      </Gated>
      <Input
        aria-label="Profile model"
        placeholder="Model"
        value={model}
        onChange={(e) => setModel(e.target.value)}
        className="w-28"
      />
      <Gated op={PROFILE_MATCH_OP}>
        <Button
          variant="outline"
          disabled={busy || (macValue === '' && serialValue === '' && modelValue === '')}
          onClick={match}
        >
          Match
        </Button>
      </Gated>
      {result && (
        <div data-testid="device-profile-lookup-result" className="text-sm">
          {result.name} ({result.role}) #{result.id}
        </div>
      )}
    </div>
  );
}
