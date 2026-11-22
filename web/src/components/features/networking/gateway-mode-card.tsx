'use client';

/**
 * GatewayModeCard — the Overlay / Edge / Transit mode selection of the
 * gateway (#2051). Apply calls SetGatewayMode (`POST /api/v1/gateway/mode`)
 * through `useGatewayMode`, the SDK GatewayService, not a hand-written fetch.
 *
 * Changing the modes reconfigures the gateway's data plane, so the card asks
 * the operator to confirm before it writes. A refusal is shown verbatim.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
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
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import {
  GATEWAY_MODE_BITS,
  maskToModes,
  modesToMask,
  useGatewayMode,
  type GatewayModeName,
} from '@/hooks/use-gateway-mode';

const MODE_LABELS: Record<GatewayModeName, string> = {
  OVERLAY: 'Overlay',
  EDGE: 'Edge',
  TRANSIT: 'Transit',
};

const MODE_NAMES = maskToModes(GATEWAY_MODE_BITS.OVERLAY | GATEWAY_MODE_BITS.EDGE | GATEWAY_MODE_BITS.TRANSIT);

function labels(modes: GatewayModeName[]): string {
  return modes.map((m) => MODE_LABELS[m]).join(' + ');
}

/** The refusal text of a SetGatewayMode status: its error, else its message. */
function statusText(status?: { error?: string | { message: string }; message?: string }): string | undefined {
  const err = typeof status?.error === 'string' ? status.error : status?.error?.message;
  return err || status?.message;
}

export interface GatewayModeCardProps {
  /** The modes the gateway runs now; the checkboxes start from them. */
  initialModes?: GatewayModeName[];
}

export function GatewayModeCard({ initialModes = [] }: GatewayModeCardProps) {
  const { setModes } = useGatewayMode();
  const { toast } = useToast();
  const [selected, setSelected] = useState<GatewayModeName[]>(() => maskToModes(modesToMask(initialModes)));
  const [busy, setBusy] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const toggle = (name: GatewayModeName, on: boolean) => {
    const mask = modesToMask(selected);
    const next = on ? mask | GATEWAY_MODE_BITS[name] : mask & ~GATEWAY_MODE_BITS[name];
    setSelected(maskToModes(next));
  };

  const apply = async () => {
    setConfirming(false);
    setBusy(true);
    try {
      const res = await setModes(selected);
      if (res.success && res.data?.status?.success !== false) {
        const applied = res.data?.gatewayStatus ? maskToModes(res.data.gatewayStatus.modes) : selected;
        toast({ title: 'Gateway modes set', description: labels(applied), variant: 'success' });
      } else if (res.success) {
        toast({
          title: 'Set gateway modes failed',
          description: statusText(res.data?.status),
          variant: 'destructive',
        });
      } else {
        toast({ title: 'Set gateway modes failed', description: res.error?.message, variant: 'destructive' });
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card data-testid="gateway-mode-card">
      <CardHeader>
        <CardTitle>Gateway modes</CardTitle>
        <CardDescription>The roles this gateway's data plane runs.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap gap-6">
          {MODE_NAMES.map((name) => {
            const id = `gw-mode-${name.toLowerCase()}`;
            return (
              <div key={name} className="flex items-center gap-2">
                <Checkbox
                  id={id}
                  aria-label={MODE_LABELS[name]}
                  checked={selected.includes(name)}
                  onCheckedChange={(v) => toggle(name, v === true)}
                />
                <Label htmlFor={id}>{MODE_LABELS[name]}</Label>
              </div>
            );
          })}
        </div>
        <Button disabled={busy || selected.length === 0} onClick={() => setConfirming(true)}>
          Apply modes
        </Button>
      </CardContent>

      <Dialog open={confirming} onOpenChange={setConfirming}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change the gateway modes?</DialogTitle>
            <DialogDescription>
              {`The data plane is reconfigured for ${labels(selected)}.`}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirming(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={() => void apply()}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
