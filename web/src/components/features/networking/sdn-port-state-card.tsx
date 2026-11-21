'use client';

/**
 * SDN port state card: GetPort and SetPortState on
 * `GET|PUT /api/v1/sdn/bridges/{name}/ports/{port}/state` through
 * useSDNPortState.
 *
 * Setting a port down cuts its traffic, so the card asks first. A zero rate
 * leaves the port's policing as it is. Refusals are shown verbatim.
 */

import { useCallback, useEffect, useState } from 'react';
import { Badge } from '@/components/ui/badge';
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
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { useSDNPortState, type PortAdminState, type PortStateInput } from '@/hooks/use-sdn-port-state';
import type { Port } from 'trusted-platform-sdk';

/** "PORT_STATUS_UP" -> "UP"; "" or undefined -> "UNKNOWN"; any other string is returned without the "PORT_STATUS_" prefix. */
export function portStatusLabel(status: string | undefined): string {
  if (!status) return 'UNKNOWN';
  return status.startsWith('PORT_STATUS_') ? status.slice('PORT_STATUS_'.length) : status;
}

/** "" (after trim) -> undefined; a finite number >= 0 -> that number; anything else -> NaN. */
export function parseRate(text: string): number | undefined {
  const trimmed = text.trim();
  if (trimmed === '') return undefined;
  const value = Number(trimmed);
  return Number.isFinite(value) && value >= 0 ? value : NaN;
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function statusVariant(label: string): 'default' | 'destructive' | 'secondary' {
  if (label === 'UP') return 'default';
  if (label === 'DOWN') return 'destructive';
  return 'secondary';
}

export interface SDNPortStateCardProps {
  bridgeId: string;
  portId: string;
}

export function SDNPortStateCard({ bridgeId, portId }: SDNPortStateCardProps) {
  const ops = useSDNPortState(bridgeId, portId);
  const [port, setPort] = useState<Port | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const res = await ops.getPort();
      if (res.success && res.data) {
        setPort(res.data.port);
        setLoadError(null);
      } else {
        setLoadError(res.error?.message ?? 'Get port failed');
      }
    } catch (err) {
      setLoadError(messageOf(err));
    }
  }, [ops]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const { toast } = useToast();
  const [adminState, setAdminState] = useState<PortAdminState>('up');
  const [ingressRate, setIngressRate] = useState('');
  const [ingressBurst, setIngressBurst] = useState('');
  const [egressRate, setEgressRate] = useState('');
  const [egressBurst, setEgressBurst] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmDown, setConfirmDown] = useState(false);

  const parsedInput = (): PortStateInput | null => {
    const rates = {
      ingressRate: parseRate(ingressRate),
      ingressBurst: parseRate(ingressBurst),
      egressRate: parseRate(egressRate),
      egressBurst: parseRate(egressBurst),
    };
    if (Object.values(rates).some((v) => v !== undefined && Number.isNaN(v))) return null;
    return { adminState, ...rates };
  };

  const send = async () => {
    const input = parsedInput();
    if (!input) return;
    setBusy(true);
    try {
      const res = await ops.setPortState(input);
      if (res.success) {
        toast({ title: 'Port state set', description: `Port ${portId} is ${input.adminState}`, variant: 'success' });
        await reload();
      } else {
        toast({
          title: 'Set port state failed',
          description: res.error?.message ?? 'request failed',
          variant: 'destructive',
        });
      }
    } catch (err) {
      toast({ title: 'Set port state failed', description: messageOf(err), variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const apply = () => {
    if (!parsedInput()) {
      toast({ title: 'Invalid rate', description: 'rates are whole numbers of bits per second', variant: 'destructive' });
      return;
    }
    if (adminState === 'down') {
      setConfirmDown(true);
      return;
    }
    void send();
  };

  const rateFields: { label: string; value: string; set: (v: string) => void }[] = [
    { label: 'Ingress rate (bps)', value: ingressRate, set: setIngressRate },
    { label: 'Ingress burst (bits)', value: ingressBurst, set: setIngressBurst },
    { label: 'Egress rate (bps)', value: egressRate, set: setEgressRate },
    { label: 'Egress burst (bits)', value: egressBurst, set: setEgressBurst },
  ];

  const label = port ? portStatusLabel(String(port.status)) : '';

  return (
    <Card>
      <CardHeader>
        <CardTitle>Port state</CardTitle>
        <CardDescription>
          Port {portId} on bridge {bridgeId}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          {port && (
            <>
              <span data-testid="sdn-port-name" className="font-mono">
                {port.config?.name ?? port.id}
              </span>
              <Badge data-testid="sdn-port-status" variant={statusVariant(label)}>
                {label}
              </Badge>
            </>
          )}
          <Button variant="outline" size="sm" onClick={() => void reload()}>
            Refresh
          </Button>
        </div>
        {loadError && (
          <p role="alert" className="text-sm text-destructive">
            {loadError}
          </p>
        )}
        <div className="space-y-2">
          <Label>Admin state and rate limits (a zero or blank rate leaves the policing as it is)</Label>
          <select
            aria-label="Admin state"
            className="h-9 rounded-md border border-input bg-background px-2 text-sm"
            value={adminState}
            onChange={(e) => setAdminState(e.target.value as PortAdminState)}
          >
            <option value="up">Up</option>
            <option value="down">Down</option>
          </select>
          <div className="grid grid-cols-2 gap-2">
            {rateFields.map((f) => (
              <Input
                key={f.label}
                aria-label={f.label}
                placeholder={f.label}
                inputMode="numeric"
                value={f.value}
                onChange={(e) => f.set(e.target.value)}
              />
            ))}
          </div>
          <Button onClick={apply} disabled={busy}>
            Apply
          </Button>
        </div>
      </CardContent>
      <Dialog open={confirmDown} onOpenChange={setConfirmDown}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Set the port down?</DialogTitle>
            <DialogDescription>
              Port {portId} on bridge {bridgeId} stops passing traffic until it is set up again.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmDown(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                setConfirmDown(false);
                void send();
              }}
            >
              Set down
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
