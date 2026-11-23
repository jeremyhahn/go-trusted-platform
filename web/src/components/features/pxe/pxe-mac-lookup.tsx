'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Gated } from '@/components/features/capabilities/gated';
import { usePXE, useToast } from '@/hooks';

const BY_MAC_OP = 'GET /api/v1/pxe/devices/mac/{mac}';

/**
 * PXEMacLookup finds a PXE device by its MAC address through the SDK
 * PXEService and opens the detail page of the device the server answers.
 * The lookup is gated on the server route it calls.
 */
export function PXEMacLookup() {
  const pxe = usePXE();
  const router = useRouter();
  const { toast } = useToast();
  const [mac, setMac] = useState('');
  const [busy, setBusy] = useState(false);

  const trimmed = mac.trim();

  const find = async (): Promise<void> => {
    if (!trimmed) {
      return;
    }
    setBusy(true);
    try {
      const res = await pxe.getDeviceByMAC(trimmed);
      if (res.success === false || !res.data?.device) {
        toast({
          title: 'PXE lookup failed',
          description: res.error?.message,
          variant: 'destructive',
        });
        return;
      }
      router.push(`/networking/pxe/${encodeURIComponent(res.data.device.id)}`);
    } catch (err) {
      toast({
        title: 'PXE lookup failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex gap-2">
      <Input
        aria-label="MAC address"
        className="h-9 w-48 font-mono"
        value={mac}
        onChange={(e) => setMac(e.target.value)}
        placeholder="02:00:00:00:00:01"
      />
      <Gated op={BY_MAC_OP}>
        <Button variant="outline" size="sm" disabled={busy || !trimmed} onClick={() => void find()}>
          <Search className="mr-2 h-4 w-4" />
          Find by MAC
        </Button>
      </Gated>
    </div>
  );
}
