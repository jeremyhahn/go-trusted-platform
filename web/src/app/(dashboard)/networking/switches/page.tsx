'use client';

import * as React from 'react';
import type { SwitchPortStatus } from 'trusted-platform-sdk';

import { Gated } from '@/components/features/capabilities/gated';
import { SwitchPortsTable } from '@/components/features/switches/switch-ports-table';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { useSwitches, useToast } from '@/hooks';

const PORT_READ_OP = 'GET /api/v1/switches/{switch}/ports/{port}';

function portVLAN(p: SwitchPortStatus): string {
  if (p.mode !== 'trunk') {
    return `VLAN ${p.access_vlan}`;
  }
  const vlans = p.trunk_vlans && p.trunk_vlans.length > 0 ? p.trunk_vlans.join(', ') : 'none';
  return p.native_vlan !== undefined ? `VLANs ${vlans} · native ${p.native_vlan}` : `VLANs ${vlans}`;
}

// ShownSwitch is the named switch's ports and the one-port status read,
// all through client.switches (#2066).
function ShownSwitch({ name }: { name: string }) {
  const sw = useSwitches(name);
  const { toast } = useToast();
  const [port, setPort] = React.useState('');
  const [status, setStatus] = React.useState<SwitchPortStatus | undefined>(undefined);

  const readStatus = async () => {
    const p = port.trim();
    if (p === '') return;
    try {
      setStatus(await sw.getPortStatus(p));
    } catch (err) {
      setStatus(undefined);
      toast({
        title: 'Switch request failed',
        description: err instanceof Error ? err.message : String(err),
        variant: 'destructive',
      });
    }
  };

  return (
    <>
      {sw.error ? (
        <Alert variant="destructive" role="alert">
          <AlertDescription>{sw.error.message}</AlertDescription>
        </Alert>
      ) : (
        <SwitchPortsTable
          switchName={name}
          ports={sw.ports}
          onEnable={sw.enablePort}
          onDisable={sw.disablePort}
          onSetVLAN={sw.setPortVLAN}
        />
      )}

      <Card>
        <CardHeader>
          <CardTitle>Port status</CardTitle>
          <CardDescription>Read one port of {name}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-end gap-2">
            <div className="space-y-1">
              <Label htmlFor="switch-port-name">Port</Label>
              <Input id="switch-port-name" value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
            <Gated op={PORT_READ_OP}>
              <Button variant="outline" disabled={port.trim() === ''} onClick={() => void readStatus()}>
                Read port status
              </Button>
            </Gated>
          </div>
          {status ? (
            <dl data-testid="switch-port-status" className="grid grid-cols-2 gap-1 text-sm">
              <dt>Port</dt>
              <dd>{status.port}</dd>
              <dt>Mode</dt>
              <dd>{status.mode}</dd>
              <dt>VLAN</dt>
              <dd>{portVLAN(status)}</dd>
              <dt>Admin</dt>
              <dd>{status.enabled ? 'Enabled' : 'Disabled'}</dd>
              <dt>Link</dt>
              <dd>{status.link_up ? 'Up' : 'Down'}</dd>
            </dl>
          ) : null}
        </CardContent>
      </Card>
    </>
  );
}

// SwitchesPage takes a managed switch's name (the server has no
// list-switches route) and shows its ports with gated writes (#2066).
export default function SwitchesPage() {
  const [name, setName] = React.useState('');
  const [shown, setShown] = React.useState('');

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Managed switches</CardTitle>
          <CardDescription>Name a switch from the daemon&apos;s switches configuration to see its ports</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (name.trim() !== '') setShown(name.trim());
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="switch-name">Switch name</Label>
              <Input id="switch-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <Button type="submit" disabled={name.trim() === ''}>
              Show ports
            </Button>
          </form>
        </CardContent>
      </Card>

      {shown !== '' ? <ShownSwitch key={shown} name={shown} /> : null}
    </div>
  );
}
