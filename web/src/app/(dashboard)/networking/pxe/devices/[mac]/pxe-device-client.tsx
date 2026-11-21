"use client";

import { useState } from 'react';
import { useParams, usePathname } from 'next/navigation';

import { PageHeader } from '@/components/layout';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { useApi } from '@/hooks';
import { pxeStateLabel, usePXEDeviceDetail } from '@/hooks/use-pxe-device-detail';
import { useToast } from '@/hooks/use-toast';
import { resolveDynamicId } from '@/utils/dynamic-route';

const STATES = [
  'DISCOVERED',
  'BOOTING',
  'INSTALLING',
  'INSTALL_COMPLETE',
  'ENROLLING',
  'ENROLLED',
  'AUTHORIZING',
  'AUTHORIZED',
  'FAILED',
  'QUARANTINED',
];

type WriteResult = { success: boolean; error?: { message?: string } };
type Pending = 'state' | 'enrolled' | 'start' | 'stop' | null;

/**
 * PXE device detail page (#2062): reads one device by MAC (GetDeviceByMAC)
 * with its provisioning events (GetEvents), sets its state (UpdateState),
 * marks it enrolled (SetDeviceEnrolled) and starts or stops the PXE service
 * (StartService, StopService), all through usePXEDeviceDetail on the SDK
 * client.
 */
export default function PXEDeviceClient() {
  const mac = resolveDynamicId(useParams(), usePathname(), 'devices', 'mac');
  const detail = usePXEDeviceDetail();
  const { toast } = useToast();

  const device = useApi(() => detail.getDeviceByMAC(mac), [detail, mac], { enabled: mac !== '' });
  const info = device.data?.device;
  const id = info?.id ?? '';
  const events = useApi(() => detail.getEvents(id), [detail, id], { enabled: id !== '' });

  const [selected, setSelected] = useState(STATES[0]);
  const [reason, setReason] = useState('');
  const [serial, setSerial] = useState('');
  const [pending, setPending] = useState<Pending>(null);

  const refresh = () => {
    void device.refetch();
    if (id !== '') {
      void events.refetch();
    }
  };

  const write = async (
    kind: Exclude<Pending, null>,
    call: () => Promise<WriteResult>,
    title: string,
    reread: boolean
  ) => {
    setPending(kind);
    try {
      const res = await call();
      if (res.success === false) {
        toast({ title: 'PXE request failed', description: res.error?.message, variant: 'destructive' });
        return;
      }
      toast({ title });
      if (reread) {
        refresh();
      }
    } finally {
      setPending(null);
    }
  };

  const sortedEvents = [...(events.data?.events ?? [])].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title={mac || 'PXE device'}
        description="PXE provisioning device"
        actions={
          <>
            <Button variant="outline" onClick={refresh}>
              Refresh
            </Button>
            <Button
              disabled={pending === 'start'}
              onClick={() => write('start', () => detail.startService(), 'PXE service started', false)}
            >
              Start PXE service
            </Button>
            <Button
              variant="outline"
              disabled={pending === 'stop'}
              onClick={() => write('stop', () => detail.stopService(), 'PXE service stopped', false)}
            >
              Stop PXE service
            </Button>
          </>
        }
      />

      {device.isError && <p role="alert">{device.error?.message}</p>}

      {info && (
        <>
          <Card data-testid="pxe-device">
            <CardHeader>
              <CardTitle>Device</CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-2 gap-2 text-sm">
                <dt>ID</dt>
                <dd>{info.id}</dd>
                <dt>MAC</dt>
                <dd>{info.macAddress}</dd>
                <dt>State</dt>
                <dd>
                  <Badge>{pxeStateLabel(info.state)}</Badge>
                </dd>
                <dt>Reason</dt>
                <dd>{info.stateReason || '-'}</dd>
                <dt>Certificate serial</dt>
                <dd>{info.certificateSerial || '-'}</dd>
                <dt>VLAN</dt>
                <dd>
                  {info.currentVlan ?? '-'} -&gt; {info.targetVlan ?? '-'}
                </dd>
                <dt>Retries</dt>
                <dd>{info.retryCount}</dd>
              </dl>
            </CardContent>
          </Card>

          <Card data-testid="pxe-state">
            <CardHeader>
              <CardTitle>State</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-2">
              <select
                aria-label="State"
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="h-9 rounded-md border px-2 text-sm"
              >
                {STATES.map((s) => (
                  <option key={s} value={s}>
                    {pxeStateLabel(s)}
                  </option>
                ))}
              </select>
              <Input
                aria-label="Reason"
                placeholder="Reason"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="max-w-xs"
              />
              <Button
                disabled={pending === 'state'}
                onClick={() =>
                  write(
                    'state',
                    () => detail.updateState(id, selected, reason.trim() || undefined),
                    'State updated',
                    true
                  )
                }
              >
                Set state
              </Button>
            </CardContent>
          </Card>

          <Card data-testid="pxe-enrolled">
            <CardHeader>
              <CardTitle>Enrolment</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap items-center gap-2">
              <span>{info.certificateSerial ? 'Enrolled' : 'Not enrolled'}</span>
              <Input
                aria-label="Certificate serial"
                placeholder="Certificate serial"
                value={serial}
                onChange={(e) => setSerial(e.target.value)}
                className="max-w-xs"
              />
              <Button
                disabled={serial.trim() === '' || pending === 'enrolled'}
                onClick={() =>
                  write('enrolled', () => detail.setEnrolled(id, serial.trim()), 'Device enrolled', true)
                }
              >
                Mark enrolled
              </Button>
            </CardContent>
          </Card>

          <Card data-testid="pxe-events">
            <CardHeader>
              <CardTitle>Events</CardTitle>
            </CardHeader>
            <CardContent>
              {events.isError ? (
                <p role="alert">{events.error?.message}</p>
              ) : sortedEvents.length === 0 ? (
                <p className="text-sm text-muted-foreground">No events recorded.</p>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr>
                      <th className="text-left">Time</th>
                      <th className="text-left">Event</th>
                      <th className="text-left">From</th>
                      <th className="text-left">To</th>
                      <th className="text-left">Error</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedEvents.map((e) => (
                      <tr key={e.id}>
                        <td>{new Date(e.timestamp).toLocaleString()}</td>
                        <td>{e.eventType}</td>
                        <td>{pxeStateLabel(e.fromState)}</td>
                        <td>{pxeStateLabel(e.toState)}</td>
                        <td>{e.error || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}
