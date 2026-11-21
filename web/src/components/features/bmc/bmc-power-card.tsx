'use client';

/**
 * BMCPowerCard runs PowerOn, PowerOff, PowerReset and PowerCycle on one BMC
 * profile: `POST /api/v1/bmc/{profileID}/power` with `{ action }`, through
 * useBMCPower. off, reset and cycle stop the host, so they ask first in a
 * dialog; on is sent at once. A refusal is shown verbatim as a destructive
 * toast.
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
import { useToast } from '@/hooks/use-toast';
import {
  BMC_POWER_ACTIONS,
  bmcPowerActionLabel,
  bmcPowerActionStopsHost,
  useBMCPower,
  type BMCPowerAction,
} from '@/hooks/use-bmc-power';

export interface BMCPowerCardProps {
  profileID: string;
  onChanged?: () => void;
}

export function BMCPowerCard({ profileID, onChanged }: BMCPowerCardProps) {
  const power = useBMCPower(profileID);
  const { toast } = useToast();
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<BMCPowerAction | null>(null);

  const send = async (a: BMCPowerAction) => {
    const label = bmcPowerActionLabel(a);
    setBusy(true);
    const res = await power.run(a);
    setBusy(false);
    if (res.success) {
      toast({ title: `${label} sent`, description: `BMC profile ${profileID}`, variant: 'success' });
      onChanged?.();
    } else {
      toast({
        title: `${label} failed`,
        description: res.error?.message ?? 'Unknown error',
        variant: 'destructive',
      });
    }
  };

  const choose = (a: BMCPowerAction) => {
    if (bmcPowerActionStopsHost(a)) {
      setPending(a);
    } else {
      void send(a);
    }
  };

  const confirm = () => {
    const a = pending;
    setPending(null);
    if (a !== null) {
      void send(a);
    }
  };

  return (
    <Card data-testid="bmc-power-card">
      <CardHeader>
        <CardTitle>Power</CardTitle>
        <CardDescription>BMC profile {profileID}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-2">
        {BMC_POWER_ACTIONS.map((a) => (
          <Button
            key={a}
            variant={bmcPowerActionStopsHost(a) ? 'destructive' : 'default'}
            disabled={busy}
            onClick={() => choose(a)}
          >
            {bmcPowerActionLabel(a)}
          </Button>
        ))}
      </CardContent>

      <Dialog
        open={pending !== null}
        onOpenChange={(o) => {
          if (!o) setPending(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{pending !== null ? bmcPowerActionLabel(pending) : ''}?</DialogTitle>
            <DialogDescription>This stops the host behind BMC profile {profileID}.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPending(null)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={confirm}>
              Confirm
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
