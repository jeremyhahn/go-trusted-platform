'use client';

import { useState } from 'react';
import { Loader2, Play, Search, Square, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { SETTABLE_PXE_STATES } from '@/hooks/use-pxe-device';
import type { UsePXEDeviceResult, UsePXEServiceControlResult } from '@/hooks/use-pxe-device';
import type { ProvisioningState } from 'trusted-platform-sdk';

/**
 * Why the install-complete webhook has no operator control: it is the
 * installer's call, unauthenticated by design (#238), and mounted only when
 * pxe.ServiceConfig.WebhookEnabled is set.
 */
export const PXE_WEBHOOK_GATE_REASON =
  'The install-complete webhook is machine-facing: the installer posts it when an install ends. ' +
  'It authenticates nobody and identifies the device by the MAC address it sends (#238), and the ' +
  'server mounts it only when the PXE webhook is enabled. Mark an install done with Set state instead.';

function Feedback({ error, notice }: { error: string | null; notice: string | null }) {
  if (error) {
    return (
      <p role="alert" className="text-sm text-red-500">
        {error}
      </p>
    );
  }
  if (notice) {
    return (
      <p role="status" className="text-sm text-muted-foreground">
        {notice}
      </p>
    );
  }
  return null;
}

/** StartService / StopService for the PXE status card. */
export function PXEServiceControls({
  running,
  control,
}: {
  running: boolean;
  control: UsePXEServiceControlResult;
}) {
  return (
    <div className="space-y-2 pt-2">
      <div className="flex gap-2">
        <Button size="sm" variant="outline" disabled={control.busy || running} onClick={() => void control.start()}>
          <Play className="mr-2 h-4 w-4" />
          Start service
        </Button>
        <Button size="sm" variant="outline" disabled={control.busy || !running} onClick={() => void control.stop()}>
          <Square className="mr-2 h-4 w-4" />
          Stop service
        </Button>
      </div>
      <Feedback error={control.error} notice={control.notice} />
    </div>
  );
}

/** The WebhookComplete control, gated off with its reason. */
export function PXEWebhookGate() {
  return (
    <div className="space-y-2">
      <Button size="sm" variant="outline" disabled aria-describedby="pxe-webhook-gate-reason">
        Send install-complete webhook
      </Button>
      <p id="pxe-webhook-gate-reason" data-testid="pxe-webhook-gate-reason" className="text-xs text-muted-foreground">
        {PXE_WEBHOOK_GATE_REASON}
      </p>
    </div>
  );
}

/**
 * Device lookup (GetDeviceByMAC, GetDevice) and the detail panel with the
 * device operations and its provisioning events.
 */
export function PXEDevicePanel({ ctl, onChanged }: { ctl: UsePXEDeviceResult; onChanged: () => void }) {
  const [mac, setMac] = useState('');
  const [quarantineReason, setQuarantineReason] = useState('');
  const [newState, setNewState] = useState<ProvisioningState>('FAILED');
  const [stateReason, setStateReason] = useState('');
  const [serial, setSerial] = useState('');
  const [vlan, setVlan] = useState('');
  const [confirmRemove, setConfirmRemove] = useState(false);

  const device = ctl.device;
  const act = async (fn: () => Promise<void>) => {
    await fn();
    onChanged();
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Device Operations</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (mac.trim()) void ctl.lookupByMAC(mac);
          }}
        >
          <div className="flex-1 space-y-2">
            <Label htmlFor="pxe-lookup-mac">Device MAC address</Label>
            <Input
              id="pxe-lookup-mac"
              value={mac}
              onChange={(e) => setMac(e.target.value)}
              placeholder="aa:bb:cc:11:22:33"
            />
          </div>
          <Button type="submit" disabled={!mac.trim() || ctl.busy}>
            {ctl.busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Search className="mr-2 h-4 w-4" />}
            Look up
          </Button>
        </form>

        <Feedback error={ctl.error} notice={ctl.notice} />

        {device && (
          <div data-testid="pxe-device-detail" className="space-y-4 rounded-lg border border-border p-4">
            <div className="flex items-start justify-between">
              <div className="space-y-1 text-sm">
                <div className="font-mono">{device.macAddress}</div>
                <div className="text-muted-foreground">
                  ID <span className="font-mono">{device.id}</span>
                </div>
                <div>
                  State{' '}
                  <Badge variant="outline" data-testid="pxe-device-state">
                    {device.state}
                  </Badge>
                </div>
                {device.stateReason && <div className="text-muted-foreground">{device.stateReason}</div>}
                {device.certificateSerial && (
                  <div className="text-muted-foreground">
                    Certificate <span className="font-mono">{device.certificateSerial}</span>
                  </div>
                )}
              </div>
              <Button size="icon" variant="ghost" aria-label="Close device" onClick={ctl.close}>
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="pxe-target-vlan">Target VLAN</Label>
                <div className="flex gap-2">
                  <Input
                    id="pxe-target-vlan"
                    type="number"
                    min={1}
                    max={4094}
                    value={vlan}
                    onChange={(e) => setVlan(e.target.value)}
                    placeholder="default"
                  />
                  <Button
                    disabled={ctl.busy}
                    onClick={() => void act(() => ctl.authorize(vlan.trim() ? Number(vlan) : undefined))}
                  >
                    Authorize
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="pxe-quarantine-reason">Quarantine reason</Label>
                <div className="flex gap-2">
                  <Input
                    id="pxe-quarantine-reason"
                    value={quarantineReason}
                    onChange={(e) => setQuarantineReason(e.target.value)}
                  />
                  <Button
                    variant="destructive"
                    disabled={ctl.busy}
                    onClick={() => void act(() => ctl.quarantine(quarantineReason))}
                  >
                    Quarantine
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="pxe-new-state">New state</Label>
                <select
                  id="pxe-new-state"
                  className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm"
                  value={newState}
                  onChange={(e) => setNewState(e.target.value as ProvisioningState)}
                >
                  {SETTABLE_PXE_STATES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
                <Label htmlFor="pxe-state-reason">State reason</Label>
                <div className="flex gap-2">
                  <Input id="pxe-state-reason" value={stateReason} onChange={(e) => setStateReason(e.target.value)} />
                  <Button disabled={ctl.busy} onClick={() => void act(() => ctl.updateState(newState, stateReason))}>
                    Set state
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="pxe-cert-serial">Certificate serial</Label>
                <div className="flex gap-2">
                  <Input id="pxe-cert-serial" value={serial} onChange={(e) => setSerial(e.target.value)} />
                  <Button
                    disabled={ctl.busy || !serial.trim()}
                    onClick={() => void act(() => ctl.setEnrolled(serial))}
                  >
                    Mark enrolled
                  </Button>
                </div>
              </div>
            </div>

            <div className="flex gap-2">
              <Button variant="outline" disabled={ctl.busy} onClick={() => void act(() => ctl.retry())}>
                Retry
              </Button>
              {confirmRemove ? (
                <>
                  <Button
                    variant="destructive"
                    disabled={ctl.busy}
                    onClick={() => {
                      setConfirmRemove(false);
                      void act(() => ctl.remove());
                    }}
                  >
                    Confirm remove
                  </Button>
                  <Button variant="outline" onClick={() => setConfirmRemove(false)}>
                    Cancel
                  </Button>
                </>
              ) : (
                <Button variant="destructive" disabled={ctl.busy} onClick={() => setConfirmRemove(true)}>
                  Remove device
                </Button>
              )}
            </div>

            <div className="space-y-2">
              <div className="text-sm font-medium">Provisioning events</div>
              {ctl.events.length === 0 ? (
                <p className="text-sm text-muted-foreground">No events recorded</p>
              ) : null}
              <ul data-testid="pxe-device-events" className="space-y-1 text-sm">
                {ctl.events.map((ev) => (
                  <li key={ev.id} className="flex gap-2">
                    <span className="text-muted-foreground">
                      {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '-'}
                    </span>
                    <span className="font-mono">{ev.eventType}</span>
                    {(ev.fromState || ev.toState) && (
                      <span>
                        {ev.fromState ?? '?'} → {ev.toState ?? '?'}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
